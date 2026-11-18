#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Classic GFSK IQ through the full pipeline; mixed BLE regression; SQLite/API isolation."""
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import numpy as np
from scipy.signal import fftconvolve
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'sink'))
sys.path.insert(0, str(ROOT/'tools'))
import w1700k_ble_sink as sink
import ble_web as web
from gen_ble_iq import gaussian_taps
BIN = Path(os.environ.get('W1700K_BLE_BUILD', ROOT/'build'))/'w1700k-ble'

class ClassicTests(unittest.TestCase):
    def test_iq(self):
        # Fixed GIAC vector, independent of the production polynomial encoder.
        sync=0x4e7a2cce331a3ae2
        bits=[(sync&1)^(i&1) for i in range(4)]+[(sync>>i)&1 for i in range(64)]
        bits += [((sync>>57)&1)^(i&1) for i in range(4)]
        bits += [(0x15555>>i)&1 for i in range(18) for j in range(3)]
        with tempfile.TemporaryDirectory() as tmp:
            for fs,lo in [(160_000_000,2441e6),(160_000_000,2441.999999e6),(320_000_000,2441e6)]:
                sps=fs//1_000_000; rng=np.random.default_rng(819)
                n=int(.007*fs); x=(rng.normal(0,8,n)+1j*rng.normal(0,8,n))
                nrz=np.repeat(np.array(bits)*2.-1,sps)
                freq=fftconvolve(nrz,gaussian_taps(sps),mode='same')
                wave=1300*np.exp(1j*np.cumsum(freq)*np.pi*.32/sps) # Classic h=.32
                truth=[]
                for i,ch in enumerate([0,1,38,39,40,77,78]):
                    t=.00065+i*.0008; start=round(t*fs)
                    carrier=(2402e6+ch*1e6-lo+17000)/fs
                    x[start:start+len(wave)] += wave*np.exp(2j*np.pi*carrier*np.arange(len(wave)))
                    truth.append((ch,t))
                path=Path(tmp)/'classic.cs16'
                iq=np.empty(n*2,dtype='<i2');iq[0::2]=x.real.astype('<i2');iq[1::2]=x.imag.astype('<i2');iq.tofile(path)
                r=subprocess.run([str(BIN),'--input',str(path),'--rate',str(fs),'--lo',str(lo),
                    '--classic','--t0','1000','--block-frames','512','--quiet'],check=True,capture_output=True)
                packets=[json.loads(l) for l in r.stdout.splitlines()]
                self.assertEqual(len(packets),len(truth),r.stderr.decode())
                for p,(ch,t) in zip(packets,truth):
                    self.assertEqual((p['kind'],p['lap'],p['classic_channel']),('classic','9e8b33',ch))
                    self.assertLess(abs(p['t_stream']-t),2e-6)
                    self.assertEqual(p['header_fec_errors'],0)
    def test_mixed_ble_regression(self):
        from test_e2e import run_case
        self.assertTrue(run_case(160e6,2441e6,.06,84,.01,0,None,False,extra_args=('--classic',)))
    def test_storage(self):
        with tempfile.TemporaryDirectory() as tmp:
            db=str(Path(tmp)/'capture.db')
            args=sink.build_parser().parse_args(['--db',db])
            s=sink.Sink(args,out=io.StringIO(),err=io.StringIO())
            now=time.time(); end=int(now-web.LAG_S)
            def emit(lap,ch,ts):
                s.handle_line(json.dumps(dict(kind='classic',lap=lap,classic_channel=ch,ts=ts,
                    rssi_dbfs=-40,cfo_khz=2,header_fec_errors=0,profile='unknown')).encode())
            emit('123456',0,end-5); emit('123456',78,end-4);s.flush()
            emit('123456',1,end-3);emit('abcdef',10,end-4);s.flush()
            for bad in [('invalid',1,now),('123456',79,now),('123456',0,float('nan'))]: emit(*bad)
            s.flush()
            self.assertEqual(s.counts['malformed'],3)
            self.assertEqual(s.conn.execute('SELECT count(*) FROM ble_packets').fetchone()[0],0)
            self.assertEqual(s.conn.execute('SELECT count(*) FROM classic_packets').fetchone()[0],4)
            api=web.api_classic(web.Db(db),{'lap':'123456'})
            self.assertEqual(api['total'],2)
            self.assertAlmostEqual(api['rate'],.4)
            self.assertEqual({c[1] for c in api['cells']},{0,1,78})
            self.assertEqual(next(x for x in api['streams'] if x['lap']=='123456')['packets'],3)
            self.assertEqual(web.api_classic(web.Db(db),{'sdr':'absent'})['total'],0)
            s.conn.close()
    def test_legacy_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            db=str(Path(tmp)/'old.db');sqlite3.connect(db).close()
            self.assertEqual(web.api_classic(web.Db(db),{})['streams'],[])

if __name__=='__main__': unittest.main()
