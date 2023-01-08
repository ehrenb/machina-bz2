import base64
import bz2
import json

from machina.core.worker import Worker

class Bz2Analysis(Worker):
    types = ['bz2']
    next_queues = ['Identifier']

    def __init__(self, *args, **kwargs):
        super(Bz2Analysis, self).__init__(*args, **kwargs)

    def callback(self, data, properties):
        data = json.loads(data)

        # resolve path
        target = self.get_binary_path(data['ts'], data['hashes']['md5'])
        self.logger.info(f"resolved path: {target}")

        with bz2.open(target, 'rb') as f:
            data_encoded = base64.b64encode(f.read()).decode()
            body = {
                "data": data_encoded,
                "origin": {
                    "ts": data['ts'],
                    "md5": data['hashes']['md5'],
                    "uid": data['uid'], 
                    "type": data['type']
                }
            }
            self.publish_next(json.dumps(body))
