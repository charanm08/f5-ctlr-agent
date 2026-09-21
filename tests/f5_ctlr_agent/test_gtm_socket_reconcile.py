import copy
import json
import threading
import unittest
from unittest.mock import MagicMock, patch

from f5_ctlr_agent import bigipconfigdriver as driver


class CredentialSocketReadTest(unittest.TestCase):
    def test_fragmented_credentials_and_large_ca_bundle(self):
        expected = {'gtm_username': 'user', 'gtm_password': 'secret', 'cert_data': 'x' * 9000}
        payload = json.dumps(expected).encode('utf-8')
        with patch.object(driver.os.path, 'exists', return_value=True), \
                patch.object(driver.socket, 'socket') as socket:
            socket.return_value.recv.side_effect = [payload[:17], payload[17:4096], payload[4096:], b'']
            self.assertEqual(expected, driver.get_credentials_from_socket('/tmp/endpoint.sock'))
            socket.return_value.connect.assert_called_once_with('/tmp/endpoint.sock')
            socket.return_value.close.assert_called_once_with()


class GTMSocketReconcileTest(unittest.TestCase):
    def setUp(self):
        self.patches = [
            patch.object(driver, 'mgmt_root', side_effect=lambda *a, **kw: MagicMock()),
            patch.object(driver, 'get_credentials_from_socket', side_effect=self.credentials),
            patch.object(driver, 'get_credentials'),
            patch.object(driver, '_create_temp_cert_file', return_value=None),
            patch.object(driver.ConfigHandler, '_sync_one_gtm'),
        ]
        mocks = [p.start() for p in self.patches]
        for p in self.patches:
            self.addCleanup(p.stop)
        self.connect, self.socket, self.fallback, self.cert, self.sync = mocks
        with patch.object(driver.threading.Thread, 'start'):
            self.handler = driver.ConfigHandler('unused', [], 30)
        self.addCleanup(self.handler.stop)
        self.config = {
            'global': {'gtm': True, 'disable-ltm': True, 'disable-arp': True},
            'bigip': {'partitions': ['Common']},
            'gtm_bigips': [
                {'url': 'https://10.1.2.10', 'socket': '/tmp/set-dns-0.sock'},
                {'url': 'https://10.1.2.11', 'socket': '/tmp/set-dns-1.sock'},
            ],
        }

    @staticmethod
    def credentials(path):
        return {'gtm_username': path, 'gtm_password': 'secret', 'cert_data': 'CA-' + path}

    def managers(self):
        return {url: w.manager for url, w in self.handler._gtm_workers.items() if w.manager is not None}

    def reconcile(self):
        workers = self.handler._reconcile_gtm_managers(self.config)
        for worker in workers:
            with worker.condition:
                version = worker.version
                self.assertTrue(worker.condition.wait_for(
                    lambda: worker.completed_version >= version, timeout=3))
        return workers

    def test_each_gtm_reads_its_own_socket(self):
        self.reconcile()
        self.assertEqual(2, len(self.managers()))
        calls = {call.args[0]: call.args[1] for call in self.connect.call_args_list}
        self.assertEqual('/tmp/set-dns-0.sock', calls['10.1.2.10'])
        self.assertEqual('/tmp/set-dns-1.sock', calls['10.1.2.11'])
        self.fallback.assert_not_called()
        self.assertEqual(2, len({m._gtm_cert_id for m in self.managers().values()}))
        self.assertNotIn('username', self.config['gtm_bigips'][0])

    def test_unchanged_list_preserves_managers_and_connections(self):
        self.reconcile()
        before = self.managers()
        self.socket.reset_mock()
        self.reconcile()
        self.assertEqual(before, self.managers())
        self.socket.assert_not_called()

    def test_socket_change_replaces_only_target_and_keeps_state(self):
        self.reconcile()
        before = self.managers()
        target = before['https://10.1.2.10']
        target._gtm.replace_gtm_config({
            'config': {'Common': {'wideIPs': [{'name': 'app.example.com'}]}},
            'activeTenants': ['tenant'],
        })
        target._gtm._pending_cleanup = {'wideIPs': ['old.example.com']}
        self.config['gtm_bigips'][0]['socket'] = '/tmp/set-dns-2.sock'
        self.socket.reset_mock()
        self.reconcile()
        after = self.managers()
        self.assertIs(before['https://10.1.2.11'], after['https://10.1.2.11'])
        self.assertIsNot(target, after['https://10.1.2.10'])
        self.assertEqual(target._gtm.get_gtm_config(), after['https://10.1.2.10']._gtm.get_gtm_config())
        self.assertEqual(target._gtm._pending_cleanup, after['https://10.1.2.10']._gtm._pending_cleanup)
        self.socket.assert_called_once_with('/tmp/set-dns-2.sock')

    def test_failed_socket_replacement_does_not_use_fallback_or_affect_peer(self):
        self.reconcile()
        before = self.managers()
        self.config['gtm_bigips'][0]['socket'] = '/tmp/unavailable.sock'
        self.socket.side_effect = lambda path: None if 'unavailable' in path else self.credentials(path)
        self.reconcile()
        self.assertEqual(before, self.managers())
        self.fallback.assert_not_called()
        self.socket.side_effect = self.credentials
        self.config['gtm_bigips'][0]['socket'] = '/tmp/recovered.sock'
        self.reconcile()
        self.assertIsNot(before['https://10.1.2.10'], self.managers()['https://10.1.2.10'])

    def test_removal_detaches_without_deleting_device_config(self):
        self.reconcile()
        before = self.managers()
        removed = self.handler._gtm_workers['https://10.1.2.10']
        self.config['gtm_bigips'].pop(0)
        self.sync.reset_mock()
        self.reconcile()
        self.assertTrue(removed.done.wait(2))
        self.assertFalse(any(call.args[0] is before['https://10.1.2.10'] for call in self.sync.call_args_list))
        self.assertIs(before['https://10.1.2.11'], self.managers()['https://10.1.2.11'])
        self.config['gtm_bigips'] = []
        self.reconcile()
        self.assertEqual({}, self.managers())

    def test_removed_endpoint_cleans_up_gtm_before_worker_detaches(self):
        self.reconcile()
        removed = self.handler._gtm_workers['https://10.1.2.10']
        removed.manager._gtm.replace_gtm_config({
            'config': {'Common': {'wideIPs': [{'name': 'wip.example.com', 'pools': []}],
                                 'pools': [], 'monitors': []}},
            'activeTenants': ['Common'],
        })
        self.config['gtm_bigips'].pop(0)

        with patch.object(self.handler, '_sync_one_gtm', wraps=self.handler._sync_one_gtm) as sync_one:
            self.handler._reconcile_gtm_managers(self.config)

        self.assertTrue(any(call.args[0] is removed.manager and call.args[1] == {'gtm': {}}
                            for call in sync_one.call_args_list))
        self.assertTrue(removed.done.wait(2))
        self.assertNotIn('https://10.1.2.10', self.handler._gtm_workers)

    def test_removal_cancels_connection_retries(self):
        self.socket.side_effect = lambda path: None
        self.reconcile()
        removed = self.handler._gtm_workers['https://10.1.2.10']
        self.config['gtm_bigips'].pop(0)
        self.handler._reconcile_gtm_managers(self.config)
        self.assertTrue(removed.done.wait(2))
        self.assertTrue(removed.stopped)
        self.assertNotIn('https://10.1.2.10', self.handler._gtm_workers)

    def test_update_gtm_reconciles_before_sync_and_isolates_mutable_config(self):
        seen = []
        def sync(mgr, config):
            seen.append(config)
            config['private'] = mgr._gtm_url
        with patch.object(self.handler, '_sync_one_gtm', side_effect=sync):
            self.reconcile()
        self.assertEqual(2, len(seen))
        self.assertIsNot(seen[0], seen[1])
        self.assertNotIn('private', self.config)

    def test_gtm_only_startup_does_not_require_default_credentials_or_ltm_url(self):
        with patch.object(driver, '_handle_args') as args, \
                patch.object(driver, '_parse_config', return_value=self.config), \
                patch.object(driver, '_handle_global_config', return_value=(30, '', '', '', '', '')), \
                patch.object(driver, '_handle_credentials') as credentials, \
                patch.object(driver, '_handle_bigip_config') as bigip_config, \
                patch.object(driver, '_set_user_agent', return_value='test'), \
                patch.object(driver, 'ConfigHandler') as handler, \
                patch.object(driver, 'ConfigWatcher'), \
                patch.object(driver, '_cleanup_temp_cert_files'):
            args.return_value.config_file = 'unused'
            self.assertEqual(0, driver.main())
        credentials.assert_not_called()
        bigip_config.assert_not_called()
        handler.assert_called_once_with('unused', [], 30, user_agent='test')

    def test_failed_connection_retries_and_new_socket_bypasses_backoff(self):
        self.socket.side_effect = lambda path: None if path.endswith('0.sock') else self.credentials(path)
        self.reconcile()
        worker = self.handler._gtm_workers['https://10.1.2.10']
        self.assertGreater(worker.retry_at, 0)
        self.socket.reset_mock()
        self.handler._reconcile_gtm_managers(self.config)
        self.assertGreater(worker.retry_at, 0)
        self.config['gtm_bigips'][0]['socket'] = '/tmp/new.sock'
        self.reconcile()
        self.socket.assert_called_once_with('/tmp/new.sock')
        self.assertEqual(2, len(self.managers()))

    def test_healthy_peer_syncs_while_other_endpoint_connects(self):
        self.reconcile()
        synced = threading.Event()
        self.config['gtm_bigips'][0]['socket'] = '/tmp/slow.sock'

        def credentials(path):
            self.assertTrue(synced.wait(2), 'healthy sync was blocked by peer connection')
            return self.credentials(path)

        self.socket.side_effect = credentials
        with patch.object(self.handler, '_sync_one_gtm', side_effect=lambda *args: synced.set()):
            self.reconcile()
        self.assertEqual('/tmp/slow.sock', self.handler._gtm_workers['https://10.1.2.10'].connected_entry['socket'])

    def test_real_manager_preprocessing_and_monitor_retry(self):
        self.reconcile()
        self.patches[-1].stop()
        mgr = self.managers()['https://10.1.2.10']
        config = {'gtm': {
            'config': {'Common': {'wideIPs': [{'name': 'example.test', 'pools': [{
                'name': 'pool', 'members': ['old'], 'member-info': [{
                    'data-server': '10.0.0.1', 'pool-member-address': '10.0.0.2',
                    'pool-member-port': 80, 'availability-zone': 'disabled',
                }],
            }]}]}},
            'activeTenants': ['tenant'], 'deletedTenants': ['old'],
            'clusterIdentifier': 'cluster', 'digitalAssetID': 'asset',
            'disabledAvailabilityZones': ['disabled'],
        }}
        with patch.object(mgr._gtm, 'create_gtm') as create:
            self.handler._sync_one_gtm(mgr, config)
        create.assert_called_once()
        self.assertEqual([], mgr._gtm.get_gtm_config()['Common']['wideIPs'][0]['pools'][0]['members'])
        self.assertEqual('cluster', mgr._gtm._snapshot_helper._local_cluster_name)
        self.assertEqual('asset', mgr._gtm._pool._cluster_digital_asset_id)
        config['gtm']['enableDataServerMonitor'] = True
        with patch.object(mgr._gtm, 'apply_monitor_settings', side_effect=RuntimeError('offline')):
            with self.assertRaises(RuntimeError):
                self.handler._sync_one_gtm(mgr, copy.deepcopy(config))
        self.assertFalse(mgr._gtm._infrastructure._enable_data_server_monitor)
        with patch.object(mgr._gtm, 'apply_monitor_settings') as monitors, \
                patch.object(mgr._gtm, 'delete_update_gtm') as crud:
            self.handler._sync_one_gtm(mgr, copy.deepcopy(config))
        monitors.assert_called_once_with('Common', config['gtm']['config'],
                                         reconcile_pool=False, reconcile_server=True)
        crud.assert_not_called()
        self.assertTrue(mgr._gtm._infrastructure._enable_data_server_monitor)

    def test_pending_cleanup_retried_with_unchanged_configuration(self):
        self.reconcile()
        self.patches[-1].stop()
        mgr = self.managers()['https://10.1.2.10']
        state = {'config': {'Common': {'wideIPs': []}}, 'activeTenants': []}
        mgr._gtm.replace_gtm_config(state)
        mgr._gtm._pending_cleanup = {'oldConfig': {}}
        with patch.object(mgr._gtm._cleanup, 'retry_pending_cleanup') as cleanup:
            self.handler._sync_one_gtm(mgr, {'gtm': state})
        cleanup.assert_called_once()
        self.assertIsNone(mgr._gtm._pending_cleanup)


class GTMEndpointWorkerUpdateTest(unittest.TestCase):
    """Unit tests for GTMEndpointWorker.update() backoff semantics."""

    def _make_worker(self, handler, url='/tmp/sock'):
        entry = {'url': 'https://10.0.0.1', 'socket': url}
        config = {'global': {}}
        worker = driver.GTMEndpointWorker(handler, entry, config)
        return worker

    def test_config_only_update_preserves_backoff(self):
        """A config-only update (same entry) must NOT reset the retry backoff.

        When a device is repeatedly failing, an unchanged connection entry means
        the same endpoint is still broken — resetting backoff here would let
        a flapping config hammer a broken device.
        """
        handler = MagicMock()
        handler._max_backoff_time = 128
        worker = self._make_worker(handler)

        future_ts = driver.time.monotonic() + 60.0
        with worker.condition:
            worker.retry_at = future_ts
            worker.backoff = 8

        new_config = {'global': {'log-level': 'debug'}}
        worker.update(worker.entry, new_config)

        with worker.condition:
            self.assertGreater(worker.retry_at, driver.time.monotonic(),
                               'backoff retry_at was reset by a config-only update')
            self.assertEqual(8, worker.backoff,
                             'backoff interval was reset by a config-only update')

    def test_entry_change_resets_backoff_immediately(self):
        """Changing the connection entry (e.g. new socket path) must reset backoff.

        A new socket means new credentials or a new endpoint — we should try
        to connect immediately rather than waiting out a penalty from the old one.
        """
        handler = MagicMock()
        handler._max_backoff_time = 128
        worker = self._make_worker(handler)

        future_ts = driver.time.monotonic() + 60.0
        with worker.condition:
            worker.retry_at = future_ts
            worker.backoff = 16

        new_entry = {'url': 'https://10.0.0.1', 'socket': '/tmp/new-sock'}
        new_config = {'global': {}}
        worker.update(new_entry, new_config)

        with worker.condition:
            self.assertEqual(0, worker.retry_at,
                             'retry_at was not reset when entry changed')
            self.assertEqual(1, worker.backoff,
                             'backoff was not reset when entry changed')


class GTMReconcileValidationTest(unittest.TestCase):
    """Tests for _reconcile_gtm_managers() input validation paths."""

    def setUp(self):
        self.patches = [
            patch.object(driver, 'mgmt_root', side_effect=lambda *a, **kw: MagicMock()),
            patch.object(driver, 'get_credentials_from_socket',
                         return_value={'gtm_username': 'u', 'gtm_password': 'p'}),
            patch.object(driver, '_create_temp_cert_file', return_value=None),
            patch.object(driver.ConfigHandler, '_sync_one_gtm'),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        with patch.object(driver.threading.Thread, 'start'):
            self.handler = driver.ConfigHandler('unused', [], 30)
        self.addCleanup(self.handler.stop)

    def _config_with(self, gtm_bigips):
        return {
            'global': {'gtm': True, 'disable-ltm': True, 'disable-arp': True},
            'bigip': {'partitions': ['Common']},
            'gtm_bigips': gtm_bigips,
        }

    def test_duplicate_url_raises_config_error(self):
        """Two entries with the same URL must raise ConfigError immediately."""
        cfg = self._config_with([
            {'url': 'https://10.1.2.10', 'socket': '/tmp/a.sock'},
            {'url': 'https://10.1.2.10', 'socket': '/tmp/b.sock'},
        ])
        with self.assertRaises(driver.ConfigError) as ctx:
            self.handler._reconcile_gtm_managers(cfg)
        self.assertIn('Duplicate', str(ctx.exception))

    def test_malformed_entry_raises_config_error(self):
        """An entry without a 'url' key must raise ConfigError."""
        cfg = self._config_with([{'socket': '/tmp/a.sock'}])
        with self.assertRaises(driver.ConfigError) as ctx:
            self.handler._reconcile_gtm_managers(cfg)
        self.assertIn('URL', str(ctx.exception))

    def test_empty_url_string_raises_config_error(self):
        """An entry with an empty URL string must raise ConfigError."""
        cfg = self._config_with([{'url': '', 'socket': '/tmp/a.sock'}])
        with self.assertRaises(driver.ConfigError) as ctx:
            self.handler._reconcile_gtm_managers(cfg)
        self.assertIn('URL', str(ctx.exception))

    def test_non_list_gtm_bigips_raises_config_error(self):
        """gtm_bigips being a dict (not a list) must raise ConfigError."""
        cfg = self._config_with({'url': 'https://10.1.2.10', 'socket': '/tmp/a.sock'})
        with self.assertRaises(driver.ConfigError) as ctx:
            self.handler._reconcile_gtm_managers(cfg)
        self.assertIn('list', str(ctx.exception))

    def test_readd_while_retiring_defers_until_done(self):
        """Re-adding a URL that is still retiring must skip that reconcile cycle."""
        cfg = self._config_with([
            {'url': 'https://10.1.2.10', 'socket': '/tmp/a.sock'},
        ])
        self.handler._reconcile_gtm_managers(cfg)
        self.assertEqual(1, len(self.handler._gtm_workers))

        url = 'https://10.1.2.10'
        worker = self.handler._gtm_workers.pop(url)
        worker.stop()
        self.handler._retiring_gtm_workers[url] = worker

        # done is NOT set — re-add must be skipped.
        self.handler._reconcile_gtm_managers(cfg)
        self.assertNotIn(url, self.handler._gtm_workers,
                         'worker was re-created while its predecessor is still retiring')

        # Mark done, then the next reconcile should reap and re-create.
        worker.done.set()
        worker.thread.join(timeout=1)
        self.handler._reconcile_gtm_managers(cfg)
        self.assertIn(url, self.handler._gtm_workers,
                      'worker was not re-created after retiring worker finished')
        self.assertNotIn(url, self.handler._retiring_gtm_workers,
                         'retiring worker entry was not cleaned up')


class GTMConnectEntryValidationTest(unittest.TestCase):
    """Tests for _connect_gtm_entry() credential / URL validation."""

    def setUp(self):
        self.patches = [
            patch.object(driver, 'mgmt_root', side_effect=lambda *a, **kw: MagicMock()),
            patch.object(driver, 'get_credentials_from_socket', return_value={}),
            patch.object(driver, '_create_temp_cert_file', return_value=None),
            patch.object(driver.ConfigHandler, '_sync_one_gtm'),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        with patch.object(driver.threading.Thread, 'start'):
            self.handler = driver.ConfigHandler('unused', [], 30)
        self.addCleanup(self.handler.stop)

    def test_non_https_url_raises_config_error(self):
        """An HTTP (non-HTTPS) URL must be rejected by _connect_gtm_entry."""
        entry = {'url': 'http://10.1.2.10', 'socket': '/tmp/a.sock'}
        config = {'global': {}}
        with self.assertRaises(driver.ConfigError) as ctx:
            self.handler._connect_gtm_entry(entry, config, None)
        self.assertIn('HTTPS', str(ctx.exception))

    def test_missing_credentials_raises_config_error(self):
        """When get_credentials_from_socket returns empty, ConfigError is raised."""
        # socket returns {} (already patched in setUp — no usable credentials)
        entry = {'url': 'https://10.1.2.10', 'socket': '/tmp/a.sock'}
        config = {'global': {}}
        with self.assertRaises(driver.ConfigError) as ctx:
            self.handler._connect_gtm_entry(entry, config, None)
        self.assertIn('credentials', str(ctx.exception).lower())

    def test_connect_failure_cleans_up_cert(self):
        """When mgmt_root() raises, the newly-written cert must be deleted."""
        cert_calls = []

        def track_cert(data, cert_id, *a):
            cert_calls.append((data, cert_id))
            return None

        with patch.object(driver, 'get_credentials_from_socket',
                          return_value={'gtm_username': 'u', 'gtm_password': 'p'}), \
             patch.object(driver, '_create_temp_cert_file', side_effect=track_cert), \
             patch.object(driver, 'mgmt_root', side_effect=RuntimeError('refused')):
            entry = {'url': 'https://10.1.2.99', 'socket': '/tmp/x.sock'}
            config = {'global': {}}
            with self.assertRaises(RuntimeError):
                self.handler._connect_gtm_entry(entry, config, None)

        # First call writes cert (non-empty data); second call deletes it (empty string).
        self.assertEqual(2, len(cert_calls),
                         'expected exactly one cert write and one cert delete')
        write_data, write_id = cert_calls[0]
        delete_data, delete_id = cert_calls[1]
        self.assertEqual(write_id, delete_id, 'cert cleanup used wrong cert_id')
        self.assertEqual('', delete_data, 'cert cleanup did not pass empty string')

    def test_reconnect_transfers_pending_cleanup_and_monitor_flag(self):
        """On reconnect, _pending_cleanup and _enable_data_server_monitor are copied."""
        old_mgr = MagicMock()
        old_mgr._gtm_cert_id = 'old-cert'
        old_mgr._gtm.get_gtm_config.return_value = {'Common': {'wideIPs': []}}
        old_mgr._gtm._active_tenants = ['t1']
        old_mgr._gtm._pending_cleanup = {'wideIPs': ['dead.example.com']}
        old_mgr._gtm._infrastructure._enable_data_server_monitor = True

        new_mgr = MagicMock()
        new_mgr._gtm_cert_id = 'new-cert'

        with patch.object(driver, 'get_credentials_from_socket',
                          return_value={'gtm_username': 'u', 'gtm_password': 'p'}), \
             patch.object(driver, '_create_temp_cert_file', return_value=None), \
             patch.object(driver, 'mgmt_root', return_value=MagicMock()), \
             patch.object(driver, 'CloudServiceManager', return_value=new_mgr):
            entry = {'url': 'https://10.1.2.50', 'socket': '/tmp/y.sock'}
            config = {'global': {}}
            self.handler._connect_gtm_entry(entry, config, old_mgr)

        new_mgr._gtm.replace_gtm_config.assert_called_once()
        call_arg = new_mgr._gtm.replace_gtm_config.call_args[0][0]
        self.assertEqual(['t1'], call_arg['activeTenants'])
        self.assertEqual({'wideIPs': ['dead.example.com']}, new_mgr._gtm._pending_cleanup)
        self.assertTrue(new_mgr._gtm._infrastructure._enable_data_server_monitor)


class GTMEndpointWorkerLifecycleTest(unittest.TestCase):
    """Tests for GTMEndpointWorker thread lifecycle and update coalescing."""

    def setUp(self):
        self.patches = [
            patch.object(driver, 'mgmt_root', side_effect=lambda *a, **kw: MagicMock()),
            patch.object(driver, 'get_credentials_from_socket',
                         side_effect=lambda path: {'gtm_username': path, 'gtm_password': 'pw'}),
            patch.object(driver, '_create_temp_cert_file', return_value=None),
            patch.object(driver.ConfigHandler, '_sync_one_gtm'),
        ]
        mocks = [p.start() for p in self.patches]
        for p in self.patches:
            self.addCleanup(p.stop)
        self.connect, self.socket, self.cert, self.sync = mocks
        with patch.object(driver.threading.Thread, 'start'):
            self.handler = driver.ConfigHandler('unused', [], 30)
        self.addCleanup(self.handler.stop)
        self.config = {
            'global': {'gtm': True, 'disable-ltm': True, 'disable-arp': True},
            'bigip': {'partitions': ['Common']},
            'gtm_bigips': [{'url': 'https://10.1.2.10', 'socket': '/tmp/set-dns-0.sock'}],
        }

    def _reconcile_and_wait(self):
        workers = self.handler._reconcile_gtm_managers(self.config)
        for w in workers:
            with w.condition:
                ver = w.version
                self.assertTrue(
                    w.condition.wait_for(lambda: w.completed_version >= ver, timeout=3))
        return workers

    def test_rapid_updates_coalesce_to_single_sync(self):
        """Multiple rapid updates while a sync is in flight coalesce to one extra sync."""
        sync_started = threading.Event()
        sync_release = threading.Event()

        def slow_sync(mgr, cfg):
            sync_started.set()
            sync_release.wait(timeout=3)

        self.sync.side_effect = slow_sync

        workers = self.handler._reconcile_gtm_managers(self.config)
        worker = workers[0]
        self.assertTrue(sync_started.wait(timeout=3), 'first sync never started')

        sync_calls_before = self.sync.call_count
        for i in range(3):
            worker.update(worker.entry, {'global': {'iteration': i}})
        sync_release.set()

        with worker.condition:
            self.assertTrue(
                worker.condition.wait_for(
                    lambda: worker.completed_version >= worker.version, timeout=3),
                'worker did not drain the coalesced updates')

        extra_syncs = self.sync.call_count - sync_calls_before
        self.assertLessEqual(extra_syncs, 1,
                             f'Expected ≤1 extra sync for 3 coalesced updates, got {extra_syncs}')

    def test_stop_calls_forget_manager_on_exit(self):
        """Stopping a worker that has a manager must call _forget_gtm_manager."""
        forget = threading.Event()
        original_forget = self.handler._forget_gtm_manager

        def track_forget(mgr):
            forget.set()
            return original_forget(mgr)

        self.handler._forget_gtm_manager = track_forget
        self._reconcile_and_wait()

        worker = self.handler._gtm_workers['https://10.1.2.10']
        self.assertIsNotNone(worker.manager, 'no manager was established')

        self.handler.stop()
        self.assertTrue(forget.wait(timeout=3),
                        '_forget_gtm_manager was not called when worker stopped')

    def test_missing_credentials_triggers_worker_retry(self):
        """Empty credentials cause ConfigError → worker enters backoff and sets pending."""
        self.socket.side_effect = lambda path: {}  # no usable credentials

        workers = self.handler._reconcile_gtm_managers(self.config)
        worker = workers[0]

        with worker.condition:
            self.assertTrue(
                worker.condition.wait_for(lambda: worker.completed_version >= 1, timeout=3),
                'worker never completed its first (failing) attempt')

        with worker.condition:
            self.assertTrue(worker.pending, 'worker should be pending for retry')
            self.assertIsNone(worker.manager, 'manager was set despite missing credentials')


class CredentialSocketEdgeCaseTest(unittest.TestCase):
    """Edge-case tests for get_credentials_from_socket()."""

    def test_socket_file_never_appears_returns_none(self):
        """If the socket file never exists within the timeout, return None."""
        start = driver.time.monotonic()
        call_count = [0]

        def fast_monotonic():
            call_count[0] += 1
            # First call establishes the loop start_time; all later calls
            # report elapsed > max_wait_seconds (10.0) so the loop exits fast.
            return start if call_count[0] == 1 else start + 11.0

        with patch.object(driver.os.path, 'exists', return_value=False), \
             patch.object(driver.time, 'monotonic', side_effect=fast_monotonic), \
             patch.object(driver.time, 'sleep'):
            result = driver.get_credentials_from_socket('/tmp/nonexistent.sock')

        self.assertIsNone(result, 'expected None when socket file never appears')

    def test_oversized_socket_response_returns_none(self):
        """A response larger than 1 MiB must be rejected and return None."""
        huge_chunk = b'x' * (1024 * 1024 + 1)

        with patch.object(driver.os.path, 'exists', return_value=True), \
             patch.object(driver.socket, 'socket') as mock_socket:
            mock_socket.return_value.recv.side_effect = [huge_chunk, b'']
            result = driver.get_credentials_from_socket('/tmp/endpoint.sock')

        self.assertIsNone(result, 'expected None for oversized socket response')


class GTMSyncOneGTMTest(unittest.TestCase):
    """Tests for ConfigHandler._sync_one_gtm() edge cases."""

    def setUp(self):
        self.patches = [
            patch.object(driver, 'mgmt_root', side_effect=lambda *a, **kw: MagicMock()),
            patch.object(driver, 'get_credentials_from_socket',
                         side_effect=lambda path: {'gtm_username': path, 'gtm_password': 'pw'}),
            patch.object(driver, '_create_temp_cert_file', return_value=None),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        with patch.object(driver.threading.Thread, 'start'):
            self.handler = driver.ConfigHandler('unused', [], 30)
        self.addCleanup(self.handler.stop)

    def _make_mgr(self):
        mgr = MagicMock()
        mgr._gtm_url = 'https://10.1.2.10'
        mgr._gtm.get_gtm_config.return_value = {}
        mgr._gtm._pending_cleanup = None
        return mgr

    def test_empty_config_with_no_prior_state_is_noop(self):
        """_sync_one_gtm with no GTM section and empty old state must be a no-op.

        The guard returns immediately without touching the device when both the
        desired config is absent and no prior config was ever pushed.
        """
        mgr = self._make_mgr()
        empty_config = {'global': {'disable-ltm': True, 'disable-arp': True}}

        self.handler._sync_one_gtm(mgr, empty_config)

        mgr._gtm.create_gtm.assert_not_called()
        mgr._gtm.delete_update_gtm.assert_not_called()
        mgr._gtm.replace_gtm_config.assert_not_called()


class ConfigHandlerShutdownTest(unittest.TestCase):
    def test_reset_notification_does_not_block_behind_api_work(self):
        entered, release = threading.Event(), threading.Event()
        config = {'global': {'disable-ltm': True, 'disable-arp': True}}
        with patch.object(driver, '_parse_config', return_value=config), \
                patch.object(driver.ConfigHandler, '_update_gtm'), \
                patch.object(driver.ConfigHandler, '_update_cccl',
                             side_effect=lambda cfg: (entered.set(), release.wait(2), 0)[-1]):
            handler = driver.ConfigHandler('unused', [], 0)
            try:
                handler.notify_reset()
                self.assertTrue(entered.wait(2))
                notified = threading.Event()
                thread = threading.Thread(target=lambda: (handler.notify_reset(), notified.set()))
                thread.start()
                self.assertTrue(notified.wait(1), 'notification blocked on API call')
            finally:
                release.set()
                handler.stop()
            thread.join(1)
            self.assertFalse(handler._thread.is_alive())

    def test_stop_joins_timer_without_holding_its_lock(self):
        with patch.object(driver.threading.Thread, 'start'):
            handler = driver.ConfigHandler('unused', [], 0)
        timer = MagicMock()
        def join():
            acquired = handler._mgr_backoff_lock.acquire(blocking=False)
            self.assertTrue(acquired, 'stop joined a timer while holding its callback lock')
            if acquired:
                handler._mgr_backoff_lock.release()
        timer.join.side_effect = join
        handler._mgr_backoff_timer['endpoint'] = timer
        handler.stop()
        timer.join.assert_called_once()

    def test_bad_snapshot_never_reuses_last_config(self):
        config = {'global': {'disable-ltm': True, 'disable-arp': True}}
        synced, rejected = threading.Event(), threading.Event()
        with patch.object(driver, '_parse_config', side_effect=[config, ValueError('invalid JSON')]), \
                patch.object(driver.ConfigHandler, '_update_cccl', return_value=0), \
                patch.object(driver.ConfigHandler, '_update_gtm', side_effect=lambda cfg: synced.set()) as sync, \
                patch.object(driver.ConfigHandler, 'handle_backoff', side_effect=lambda: rejected.set()):
            handler = driver.ConfigHandler('unused', [], 0)
            try:
                handler.notify_reset()
                self.assertTrue(synced.wait(2))
                handler.notify_reset()
                self.assertTrue(rejected.wait(2))
                sync.assert_called_once_with(config)
            finally:
                handler.stop()

    def test_certificate_write_failure_is_not_unverified_connection(self):
        with patch.object(driver.tempfile, 'NamedTemporaryFile', side_effect=OSError('disk full')):
            with self.assertRaises(driver.ConfigError):
                driver._create_temp_cert_file('CA data', 'failed-test-cert')


if __name__ == '__main__':
    unittest.main()