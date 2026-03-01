#!/usr/bin/env python3
"""
WSHawk Team Collaboration Engine
=================================
Manages multiplayer pentesting sessions: room lifecycle, operator presence,
real-time state synchronization, activity logging, and collaborative notes.

This module is framework-agnostic. It manages state and returns action
descriptors that the transport layer (gui_bridge.py / Socket.IO) executes.
"""

import random
import string
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple


# ── Operator Color Palette ──────────────────────────────────────────
# Curated for high contrast on dark backgrounds. No two adjacent
# operators should be visually confusable.
OPERATOR_COLORS = [
    '#3b82f6',  # blue
    '#ef4444',  # red
    '#22c55e',  # green
    '#f59e0b',  # amber
    '#8b5cf6',  # violet
    '#ec4899',  # pink
    '#06b6d4',  # cyan
    '#f97316',  # orange
    '#14b8a6',  # teal
    '#6366f1',  # indigo
]


class Operator:
    """Represents a connected team member."""

    __slots__ = ('sid', 'name', 'color', 'joined_at', 'cursor', 'active_tab')

    def __init__(self, sid: str, name: str, color: str):
        self.sid = sid
        self.name = name
        self.color = color
        self.joined_at = datetime.now().isoformat()
        self.cursor: Optional[Dict] = None
        self.active_tab: str = 'dashboard'

    def to_dict(self) -> Dict[str, Any]:
        return {
            'sid': self.sid,
            'name': self.name,
            'color': self.color,
            'joined_at': self.joined_at,
            'cursor': self.cursor,
            'active_tab': self.active_tab,
        }


class ActivityEntry:
    """A single event in the team activity log."""

    __slots__ = ('type', 'operator', 'color', 'time', 'data')

    def __init__(self, entry_type: str, operator: str, color: str, data: Optional[Dict] = None):
        self.type = entry_type
        self.operator = operator
        self.color = color
        self.time = datetime.now().isoformat()
        self.data = data or {}

    def to_dict(self) -> Dict[str, Any]:
        result = {
            'type': self.type,
            'operator': self.operator,
            'color': self.color,
            'time': self.time,
        }
        result.update(self.data)
        return result


class TeamRoom:
    """Encapsulates all state for a single collaboration room."""

    def __init__(self, room_code: str, created_by: str, target: str = ''):
        self.code = room_code
        self.created_at = datetime.now().isoformat()
        self.created_by = created_by
        self.target = target
        self.operators: Dict[str, Operator] = {}
        self.shared_notes: str = ''
        self.shared_endpoints: List[Dict] = []
        self.activity_log: List[ActivityEntry] = []

    @property
    def sio_room(self) -> str:
        """Socket.IO room identifier."""
        return f'team_{self.code}'

    @property
    def operator_count(self) -> int:
        return len(self.operators)

    @property
    def is_empty(self) -> bool:
        return self.operator_count == 0

    def next_color(self) -> str:
        """Assign a color that isn't currently in use."""
        used = {op.color for op in self.operators.values()}
        for color in OPERATOR_COLORS:
            if color not in used:
                return color
        # Fallback: cycle
        return OPERATOR_COLORS[self.operator_count % len(OPERATOR_COLORS)]

    def add_operator(self, sid: str, name: str) -> Operator:
        color = self.next_color()
        op = Operator(sid, name, color)
        self.operators[sid] = op
        self._log('join', name, color)
        return op

    def remove_operator(self, sid: str) -> Optional[Operator]:
        op = self.operators.pop(sid, None)
        if op:
            self._log('leave', op.name, op.color)
        return op

    def get_operator(self, sid: str) -> Optional[Operator]:
        return self.operators.get(sid)

    def roster(self) -> List[Dict]:
        return [op.to_dict() for op in self.operators.values()]

    def update_notes(self, content: str) -> None:
        self.shared_notes = content

    def add_endpoint(self, endpoint: Dict) -> None:
        self.shared_endpoints.append(endpoint)

    def _log(self, entry_type: str, operator: str, color: str, data: Optional[Dict] = None) -> ActivityEntry:
        entry = ActivityEntry(entry_type, operator, color, data)
        self.activity_log.append(entry)
        return entry

    def log_scan(self, operator: str, color: str, scan_type: str,
                 target: str, status: str, results_count: int = 0) -> ActivityEntry:
        return self._log('scan', operator, color, {
            'scan_type': scan_type,
            'target': target,
            'status': status,
            'results_count': results_count,
        })

    def log_finding(self, operator: str, color: str, finding: Dict) -> ActivityEntry:
        return self._log('finding', operator, color, {'finding': finding})

    def info(self) -> Dict[str, Any]:
        return {
            'room_code': self.code,
            'created_at': self.created_at,
            'created_by': self.created_by,
            'target': self.target,
            'operators': self.roster(),
            'shared_notes': self.shared_notes,
            'shared_endpoints': self.shared_endpoints,
            'activity_count': len(self.activity_log),
        }


class TeamEngine:
    """
    Core team collaboration engine.

    Manages room lifecycle and operator presence. All methods return
    plain data; the transport layer (gui_bridge.py) is responsible for
    emitting Socket.IO events and returning HTTP responses.
    """

    def __init__(self):
        self._rooms: Dict[str, TeamRoom] = {}
        self._sid_to_room: Dict[str, str] = {}

    # ── Room Code Generation ────────────────────────────────────────

    @staticmethod
    def _generate_code(length: int = 6) -> str:
        """Generate a human-readable uppercase alphanumeric room code."""
        # Exclude confusable characters: O/0, I/1, L
        charset = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'
        return ''.join(random.choices(charset, k=length))

    # ── Room Lifecycle ──────────────────────────────────────────────

    def create_room(self, creator_name: str, target: str = '') -> TeamRoom:
        """Create a new collaboration room and return it."""
        code = self._generate_code()
        while code in self._rooms:
            code = self._generate_code()

        room = TeamRoom(code, creator_name, target)
        self._rooms[code] = room
        return room

    def get_room(self, code: str) -> Optional[TeamRoom]:
        """Look up a room by code (case insensitive)."""
        return self._rooms.get(code.upper())

    def get_room_for_sid(self, sid: str) -> Optional[TeamRoom]:
        """Return the room the given SID is currently in."""
        code = self._sid_to_room.get(sid)
        return self._rooms.get(code) if code else None

    def destroy_room(self, code: str) -> None:
        """Remove a room entirely."""
        room = self._rooms.pop(code.upper(), None)
        if room:
            for sid in list(room.operators.keys()):
                self._sid_to_room.pop(sid, None)

    # ── Operator Lifecycle ──────────────────────────────────────────

    def join_room(self, code: str, sid: str, name: str) -> Tuple[Optional[TeamRoom], Optional[Operator]]:
        """
        Add an operator to a room.
        Returns (room, operator) or (None, None) if room not found.
        """
        room = self.get_room(code)
        if not room:
            return None, None

        op = room.add_operator(sid, name)
        self._sid_to_room[sid] = room.code
        return room, op

    def leave_room(self, sid: str) -> Tuple[Optional[TeamRoom], Optional[Operator]]:
        """
        Remove an operator from their current room.
        Returns (room, operator) or (None, None).
        Auto-destroys empty rooms.
        """
        code = self._sid_to_room.pop(sid, None)
        if not code:
            return None, None

        room = self._rooms.get(code)
        if not room:
            return None, None

        op = room.remove_operator(sid)

        if room.is_empty:
            self._rooms.pop(code, None)

        return room, op

    def leave_room_by_name(self, code: str, name: str) -> bool:
        """
        Remove an operator by name (used from REST where SID is unknown).
        Returns True if found and removed.
        """
        room = self.get_room(code)
        if not room:
            return False

        for sid, op in list(room.operators.items()):
            if op.name == name:
                room.remove_operator(sid)
                self._sid_to_room.pop(sid, None)
                if room.is_empty:
                    self._rooms.pop(room.code, None)
                return True
        return False

    # ── State Operations ────────────────────────────────────────────

    def update_notes(self, sid: str, content: str) -> Optional[Tuple[TeamRoom, Operator]]:
        """Update shared notes for the room the operator is in."""
        room = self.get_room_for_sid(sid)
        if not room:
            return None
        op = room.get_operator(sid)
        if not op:
            return None
        room.update_notes(content)
        return room, op

    def update_cursor(self, sid: str, position: Any, tab: str = 'notes') -> Optional[Tuple[TeamRoom, Operator]]:
        """Update cursor position for live cursors."""
        room = self.get_room_for_sid(sid)
        if not room:
            return None
        op = room.get_operator(sid)
        if not op:
            return None
        op.cursor = position
        op.active_tab = tab
        return room, op

    def add_endpoint(self, sid: str, endpoint: Dict) -> Optional[Tuple[TeamRoom, Operator]]:
        """Add a discovered endpoint to the shared map."""
        room = self.get_room_for_sid(sid)
        if not room:
            return None
        op = room.get_operator(sid)
        if not op:
            return None
        room.add_endpoint(endpoint)
        return room, op

    def log_scan_event(self, sid: str, scan_type: str, target: str,
                       status: str, results_count: int = 0) -> Optional[Tuple[TeamRoom, ActivityEntry]]:
        """Log a scan event to the room's activity feed."""
        room = self.get_room_for_sid(sid)
        if not room:
            return None
        op = room.get_operator(sid)
        if not op:
            return None
        entry = room.log_scan(op.name, op.color, scan_type, target, status, results_count)
        return room, entry

    def log_finding(self, sid: str, finding: Dict) -> Optional[Tuple[TeamRoom, ActivityEntry]]:
        """Log a vulnerability finding to the room's activity feed."""
        room = self.get_room_for_sid(sid)
        if not room:
            return None
        op = room.get_operator(sid)
        if not op:
            return None
        entry = room.log_finding(op.name, op.color, finding)
        return room, entry

    # ── Diagnostics ─────────────────────────────────────────────────

    @property
    def active_rooms(self) -> int:
        return len(self._rooms)

    @property
    def total_operators(self) -> int:
        return sum(r.operator_count for r in self._rooms.values())

    def stats(self) -> Dict[str, Any]:
        return {
            'active_rooms': self.active_rooms,
            'total_operators': self.total_operators,
            'rooms': {code: room.operator_count for code, room in self._rooms.items()},
        }
