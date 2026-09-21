#!/usr/bin/env python3
"""
Focused unit tests for the GTM empty-config deletion fix in _sync_one_gtm().

Tests three distinct scenarios:
  1. Empty allConfig + oldGtmConfig is empty   -> no-op (return early, no API call)
  2. Empty allConfig + oldGtmConfig has data   -> delete_update_gtm called with
                                                  empty desired state, local state cleared
  3. Non-empty allConfig                       -> normal create path unchanged
"""

import unittest
from unittest.mock import MagicMock
from f5_cccl.exceptions import F5CcclError
from f5_ctlr_agent.bigipconfigdriver import CloudServiceManager, ConfigHandler


def _make_gtm_manager(old_gtm_config):
    mgr = CloudServiceManager(MagicMock(), 'Common', gtm=True, gtm_url='https://gtm-device-1')
    mgr._gtm.replace_gtm_config({
        'config': old_gtm_config,
        'activeTenants': ['Common'] if old_gtm_config else [],
    })
    mgr._gtm.delete_update_gtm = MagicMock()
    return mgr


def _make_handler(mgr):
    handler = MagicMock(spec=ConfigHandler)
    handler._managers = [mgr]
    handler._sync_one_gtm = ConfigHandler._sync_one_gtm.__get__(handler, ConfigHandler)
    return handler


class TestSyncOneGtmEmptyConfigFix(unittest.TestCase):

    def test_empty_allconfig_and_empty_old_config_is_noop(self):
        """gtm key absent + no prior config -> no-op, no API call."""
        mgr = _make_gtm_manager(old_gtm_config={})
        handler = _make_handler(mgr)
        handler._sync_one_gtm(mgr, {'bigip': {}, 'resources': {}})
        mgr._gtm.delete_update_gtm.assert_not_called()
        self.assertEqual(mgr._gtm._gtm_config, {})

    def test_empty_allconfig_with_existing_config_triggers_delete(self):
        """gtm key removed + prior config exists -> empty-config push + state cleared."""
        old_config = {
            'Common': {
                'wideIPs':  [{'name': 'wip1.example.com', 'pools': []}],
                'pools':    [{'name': 'pool1'}],
                'monitors': [{'name': 'mon1', 'type': 'http'}],
            }
        }
        mgr = _make_gtm_manager(old_gtm_config=old_config)
        handler = _make_handler(mgr)
        handler._sync_one_gtm(mgr, {'bigip': {}, 'resources': {}})

        mgr._gtm.delete_update_gtm.assert_called_once()
        call_args = mgr._gtm.delete_update_gtm.call_args
        partition = call_args[0][0]
        empty_cfg = call_args[0][1]

        self.assertEqual(partition, 'Common')
        self.assertIn('Common', empty_cfg)
        self.assertEqual(empty_cfg['Common']['wideIPs'],  [])
        self.assertEqual(empty_cfg['Common']['pools'],    [])
        self.assertEqual(empty_cfg['Common']['monitors'], [])
        self.assertEqual(mgr._gtm._gtm_config,      {})
        self.assertEqual(mgr._gtm._active_tenants,  [])
        self.assertEqual(mgr._gtm._deleted_tenants, [])

    def test_empty_allconfig_delete_failure_propagates_for_backoff(self):
        """delete_update_gtm raises -> exception propagates, state NOT cleared."""
        old_config = {'Common': {'wideIPs': [{'name': 'wip1', 'pools': []}],
                                 'pools': [], 'monitors': []}}
        mgr = _make_gtm_manager(old_gtm_config=old_config)
        mgr._gtm.delete_update_gtm.side_effect = F5CcclError(msg='network timeout')
        handler = _make_handler(mgr)
        with self.assertRaises(F5CcclError):
            handler._sync_one_gtm(mgr, {'bigip': {}, 'resources': {}})
        self.assertEqual(mgr._gtm._gtm_config,     old_config)
        self.assertEqual(mgr._gtm._active_tenants, ['Common'])

    def test_normal_path_with_gtm_config_unchanged(self):
        """allConfig present -> normal initial create path, no teardown call."""
        mgr = _make_gtm_manager(old_gtm_config={})
        mgr._gtm.create_gtm         = MagicMock()
        mgr._gtm.replace_gtm_config = MagicMock()
        handler = _make_handler(mgr)
        new_config = {'Common': {'wideIPs': [{'name': 'wip1.example.com', 'pools': []}],
                                 'pools': [], 'monitors': [], 'dataCenter': 'dc1'}}
        config_with_gtm = {'gtm': {'config': new_config, 'activeTenants': ['Common']}}
        handler._sync_one_gtm(mgr, config_with_gtm)
        mgr._gtm.create_gtm.assert_called_once_with('Common', new_config)
        mgr._gtm.replace_gtm_config.assert_called_once()
        empty = {'Common': {'wideIPs': [], 'pools': [], 'monitors': []}}
        for c in mgr._gtm.delete_update_gtm.call_args_list:
            self.assertNotEqual(c[0][1] if len(c[0]) > 1 else {}, empty)


if __name__ == '__main__':
    print("=" * 70)
    print("Running GTM empty-config fix unit tests")
    print("=" * 70)
    unittest.main(verbosity=2)
