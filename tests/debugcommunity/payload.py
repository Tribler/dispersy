from ...payload import Payload


class TextPayload(Payload):

    """
    TextPayload is used to hold a single string.
    """
    class Implementation(Payload.Implementation):

        def __init__(self, meta, text):
            assert isinstance(text, str)
            super(TextPayload.Implementation, self).__init__(meta)
            self._text = text

        @property
        def text(self):
            return self._text
