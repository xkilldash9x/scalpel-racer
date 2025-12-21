# tests/mock_h2.py
"""
Centralized mock objects for H2 events to ensure consistency across tests
and satisfy mypy type checking.
"""

class MockStreamEnded:
    def __init__(self, stream_id=1):
        self.stream_id = stream_id

class MockResponseReceived:
    def __init__(self, stream_id=1, headers=None, stream_ended=False):
        self.stream_id = stream_id
        self.headers = headers if headers is not None else []
        self.stream_ended = stream_ended

class MockTrailersReceived:
    def __init__(self, stream_id=1, headers=None):
        self.stream_id = stream_id
        self.headers = headers if headers is not None else []

class MockStreamReset:
    def __init__(self, stream_id=1, error_code=0):
        self.stream_id = stream_id
        self.error_code = error_code

class MockRequestReceived:
    def __init__(self, stream_id=1, headers=None, stream_ended=False):
        self.stream_id = stream_id
        self.headers = headers if headers is not None else []
        self.stream_ended = stream_ended

class MockWindowUpdated:
    def __init__(self, stream_id=1, delta=0):
        self.stream_id = stream_id
        self.delta = delta

class MockDataReceived:
    def __init__(self, stream_id=1, data=b'', flow_controlled_length=0, stream_ended=False):
        self.stream_id = stream_id
        self.data = data
        self.flow_controlled_length = flow_controlled_length
        self.stream_ended = stream_ended
