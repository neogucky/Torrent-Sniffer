"""Bounded, process-local login throttling for the single-worker deployment."""
import math
import threading
import time
from collections import OrderedDict, deque

from fastapi import HTTPException


class LoginLimiter:
    def __init__(self, clock=time.monotonic, window=300, account_limit=10, client_limit=100, max_keys=10000):
        self.clock, self.window = clock, window
        self.account_limit, self.client_limit, self.max_keys = account_limit, client_limit, max_keys
        self.attempts = OrderedDict()
        self.lock = threading.Lock()

    def check(self, username, client):
        now = self.clock()
        keys = [(('account', username.casefold()), self.account_limit), (('client', client), self.client_limit)]
        with self.lock:
            while self.attempts and next(iter(self.attempts.values()))[-1] <= now - self.window:
                self.attempts.popitem(last=False)
            for key, limit in keys:
                attempts = self.attempts.get(key, deque())
                while attempts and attempts[0] <= now - self.window:
                    attempts.popleft()
                if len(attempts) >= limit:
                    self._reject(max(1, math.ceil(attempts[0] + self.window - now)))
            if len(self.attempts) + sum(key not in self.attempts for key, _ in keys) > self.max_keys:
                self._reject(self.window)
            for key, _ in keys:
                self.attempts.setdefault(key, deque()).append(now)
                self.attempts.move_to_end(key)

    def succeeded(self, username):
        with self.lock:
            self.attempts.pop(('account', username.casefold()), None)

    @staticmethod
    def _reject(seconds):
        raise HTTPException(429, 'Too many login attempts. Please try again shortly.', headers={'Retry-After': str(seconds)})


login_limiter = LoginLimiter()
