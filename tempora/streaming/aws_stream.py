from typing import Iterator
import time

try:
    import boto3
except ImportError:
    boto3 = None

class CloudWatchStreamer:
    """
    Optional plugin that polls AWS CloudWatch log groups natively.
    Requires `pip install "tempora[aws]"`.
    """
    def __init__(self, log_group: str, log_stream: str = None):
        if not boto3:
            raise ImportError("The 'boto3' library is required for AWS streaming. Please run: pip install \"tempora[aws]\"")
        self.log_group = log_group
        self.log_stream = log_stream
        self.client = boto3.client('logs')
        self.next_token = None

    def stream_events(self, poll_interval: int = 5) -> Iterator[str]:
        """
        Continuously polls CloudWatch Logs and yields raw event strings.
        """
        while True:
            kwargs = {
                'logGroupName': self.log_group,
                'startFromHead': False
            }
            if self.log_stream:
                kwargs['logStreamNames'] = [self.log_stream]
            if self.next_token:
                kwargs['nextToken'] = self.next_token
                
            response = self.client.filter_log_events(**kwargs)
            self.next_token = response.get('nextToken')
            
            for event in response.get('events', []):
                yield event['message']
                
            time.sleep(poll_interval)
