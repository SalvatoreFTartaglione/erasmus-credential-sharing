import json
import sys

class MyTestCase:

    def print_vc_dim(self, vc):
        vc_json = json.dumps(vc, separators=(',', ':'), ensure_ascii=False)
        vc_size = sys.getsizeof(vc_json.encode('utf-8'))
        print(f"Dimensione VC: {vc_size} bytes")
        return vc_size

    def print_vp_dim(self, vp):
        vp_json = json.dumps(vp, separators=(',', ':'), ensure_ascii=False)
        vp_size = sys.getsizeof(vp_json.encode('utf-8'))
        print(f"Dimensione VP: {vp_size} bytes")
        return vp_size
