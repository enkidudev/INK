import os, tempfile, unittest, sqlite3
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch
from ink.cli import Book, export, add, searchable, parser, run, root
from types import SimpleNamespace

class InkTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.env=patch.dict(os.environ,INK_HOME=self.tmp.name);self.env.start();self.addCleanup(self.env.stop)
        with patch('getpass.getpass',return_value='test-passphrase'):
            self.b=Book('pale',True)
        self.addCleanup(self.b.db.close)
    def record(self):
        return dict(user='kim',secret='secret-marker',type='password',domain='revachol',host='WS01',service='SMB',source='config',created='today',events=[{'at':'today','kind':'note','text':'</script><script>alert(1)</script>'}])
    def test_encrypted_persistence_and_wrong_password(self):
        self.b.save(self.record())
        self.assertNotIn(b'secret-marker',Path(self.tmp.name,'pale.db').read_bytes())
        with patch('getpass.getpass',return_value='test-passphrase'):
            reopened=Book('pale');self.assertEqual(reopened.records()[0]['user'],'kim');reopened.db.close()
        with patch('getpass.getpass',return_value='wrong'),self.assertRaises(ValueError):Book('pale')
    def test_export_clears_only_selected_notebook_and_advances_volume(self):
        self.b.save(self.record())
        with patch('getpass.getpass',return_value='other-pass'):other=Book('other',True)
        other.save(self.record());self.addCleanup(other.db.close)
        out=Path(self.tmp.name,'report.html');export(self.b,out)
        self.assertEqual(self.b.records(),[]);self.assertEqual(len(other.records()),1)
        self.assertEqual(self.b.db.execute("SELECT v FROM meta WHERE k='volume'").fetchone()[0],'2')
        self.assertNotIn('</script><script>alert',out.read_text())
        self.assertIn('\\u003c/script',out.read_text())
        self.assertEqual(out.stat().st_mode & 0o777,0o600)
    def test_export_failure_preserves_entries(self):
        self.b.save(self.record())
        for out in [Path(self.tmp.name,'missing','report.html'),Path(self.tmp.name,'exists.html')]:
            if out.name=='exists.html':out.write_text('keep')
            with self.assertRaises((ValueError,OSError)):export(self.b,out)
            self.assertEqual(len(self.b.records()),1)
        self.assertEqual(Path(self.tmp.name,'exists.html').read_text(),'keep')
    def test_append_and_stable_ids(self):
        self.b.save(self.record());r=self.b.pick(1);r['events'].append({'at':'later','kind':'access','host':'DC01','result':'valid'});self.b.save(r)
        self.assertEqual(len(self.b.pick(1)['events']),2)
        export(self.b,Path(self.tmp.name,'r.html'));self.b.save(self.record());self.assertEqual(self.b.records()[0]['id'],2)
    def test_bulk_mismatch_no_writes(self):
        a=SimpleNamespace(bulk=True,**{k:None for k in ('user','secret','type','domain','host','service','source')})
        with patch('builtins.input',side_effect=['comma','kim,harry,cuno']),patch('getpass.getpass',return_value='one,two'),self.assertRaises(ValueError):add(self.b,a)
        self.assertEqual(self.b.records(),[])
    def test_bulk_pairing(self):
        a=SimpleNamespace(bulk=True,user=None,secret=None,type='password',domain='',host='',service='',source='')
        with patch('builtins.input',side_effect=['comma','kim,harry,cuno','yes']),patch('getpass.getpass',return_value='pass2,vodka,pig'):add(self.b,a)
        self.assertEqual([(r['user'],r['secret']) for r in self.b.records()],[('kim','pass2'),('harry','vodka'),('cuno','pig')])
    def test_export_keep_preserves_notebook_and_volume(self):
        self.b.save(self.record())
        out = Path(self.tmp.name, 'copy.html')
        export(self.b, out, clear=False)
        self.assertTrue(out.exists())
        self.assertEqual(len(self.b.records()), 1)
        self.assertEqual(self.b.db.execute("SELECT v FROM meta WHERE k='volume'").fetchone()[0], '1')

    def test_creation_failure_cleans_up_empty_database(self):
        with patch('getpass.getpass', side_effect=['one', 'two']), self.assertRaises(ValueError):
            Book('mismatch', True)
        self.assertFalse(Path(self.tmp.name, 'mismatch.db').exists())
        with patch('getpass.getpass', return_value=''), self.assertRaises(ValueError):
            Book('empty', True)
        self.assertFalse(Path(self.tmp.name, 'empty.db').exists())

    def test_secret_is_not_a_cli_argument_and_not_searchable(self):
        self.assertFalse(any('--secret' in action.option_strings
                             for action in parser()._actions))
        self.assertNotIn('secret-marker', searchable(self.record()))
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            parser().parse_args(['add', 'pale', '--secret', 'exposed'])

    def test_symlinked_notebook_is_rejected(self):
        target = Path(self.tmp.name, 'pale.db')
        link = Path(self.tmp.name, 'linked.db')
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest('Symlinks unavailable')
        with self.assertRaisesRegex(ValueError, 'symbolic link'):
            Book('linked')

    def test_import_invalid_row_does_not_change_data(self):
        path = Path(self.tmp.name, 'broken.csv')
        path.write_text('user,secret\nvalid,abc\n,missing-user\n', encoding='utf-8')
        args = parser().parse_args(['import', 'pale', str(path)])
        with patch('getpass.getpass', return_value='test-passphrase'), self.assertRaisesRegex(ValueError, 'requires a user'):
            run(args)
        self.assertEqual(self.b.records(), [])

    def test_bulk_user_abort_is_atomic(self):
        a = SimpleNamespace(bulk=True, user=None, type='password', domain='revachol', host='WS01', service='SMB', source='source')
        self.b.save(self.record())
        count = len(self.b.records())
        # One new user followed by an existing record; abort at the merge prompt.
        with patch('builtins.input', side_effect=['comma', 'new,kim', 'yes', EOFError]), \
             patch('getpass.getpass', return_value='newpass,secret-marker'), \
             self.assertRaises(EOFError):
            add(self.b, a)
        self.assertEqual(len(self.b.records()), count)

    def test_duplicate_pairs_in_same_batch_do_not_double_insert(self):
        a = SimpleNamespace(bulk=True, user=None, type='password', domain='X', host='Y', service='', source='evidence')
        with patch('builtins.input', side_effect=['comma', 'kim,kim', 'yes', 'yes']), \
             patch('getpass.getpass', return_value='pass,pass'):
            add(self.b, a)
        records = self.b.records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['events'][0]['kind'], 'source')

    def test_name_traversal(self):
        with self.assertRaises(ValueError):Book('../escape',True)

if __name__=='__main__':unittest.main()
