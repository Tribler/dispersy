class Message(object):
    """
    An unchecked message from the wire
    """
    def __init__(self):
        # the community identifier
        self.cid = None

        # the public key of the user who signed the message
        self.signed_by = None

        # the last known global counter + 1 (from the user who signed
        # the message)
        self.global_counter = None

        # the local counter (from the user who signed the messaged)
        self.local_counter = None

        # True when this message is part of the global state
        self.in_state = None

        # a list containing actions
        self.actions = None

