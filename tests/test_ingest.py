"""
Unit tests for Zeek and Suricata log parsers.
"""
import pytest
from ndr.ingest.zeek_parser import ZeekParser
from ndr.ingest.suricata_parser import SuricataParser


def test_zeek_tsv_parser():
    fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"]
    line = "1700000000.123\tC12345\t192.168.1.100\t54321\t10.0.0.5\t443\ttcp\tssl\t2.500\t1024\t4096\tSF\tShADadFf\t10\t1500\t12\t5000"
    
    rec = ZeekParser.parse_conn_line_tsv(line, fields)
    assert rec is not None
    assert rec.uid == "C12345"
    assert rec.src_ip == "192.168.1.100"
    assert rec.src_port == 54321
    assert rec.dst_ip == "10.0.0.5"
    assert rec.dst_port == 443
    assert rec.proto == "tcp"
    assert rec.duration == 2.500
    assert rec.orig_bytes == 1024
    assert rec.resp_bytes == 4096


def test_suricata_eve_parser():
    eve_alert_json = '''{
        "timestamp": "2026-08-18T12:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": "192.168.1.200",
        "src_port": 49152,
        "dest_ip": "10.0.0.1",
        "dest_port": 22,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2001219,
            "rev": 19,
            "signature": "ET SCAN Potential SSH Scan",
            "category": "Attempted Information Leak",
            "severity": 2
        }
    }'''

    alert = SuricataParser.parse_eve_line(eve_alert_json)
    assert alert is not None
    assert alert.src_ip == "192.168.1.200"
    assert alert.dst_port == 22
    assert alert.signature_id == 2001219
    assert alert.severity == 2
    assert "SSH Scan" in alert.signature
