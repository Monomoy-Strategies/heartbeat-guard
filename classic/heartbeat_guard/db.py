#!/usr/bin/env python3
"""
Initialize the heartbeat analytics database with required schema.
"""

import sqlite3
import os

def init_database():
    """Initialize the heartbeat analytics database with all required tables."""
    
    # Database path
    db_path = os.path.expanduser("~/clawd/data/heartbeat-analytics.db")
    
    # Ensure the data directory exists
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    # Connect and create tables
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Enable foreign keys
    cursor.execute("PRAGMA foreign_keys = ON;")
    
    # Create notifications table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            notification_type TEXT NOT NULL,  -- 'email_triage', 'idea', 'briefing', 'alert', 'security', 'heartbeat_report'
            category TEXT,                     -- subcategory (e.g., 'spam', 'action_required', 'financial')
            sender TEXT,                       -- who/what generated (e.g., email sender, system)
            subject TEXT,                      -- brief description
            content_summary TEXT,              -- what was in the notification
            urgency TEXT DEFAULT 'fyi',        -- fyi, notice, alert, urgent, critical
            channel TEXT DEFAULT 'telegram',   -- delivery channel
            sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            action_taken TEXT,                 -- 'acted', 'ignored', 'trashed', 'archived', 'left', 'rated', 'project', 'backburner'
            action_detail TEXT,                -- specific action (e.g., 'RATE5', 'FOLD_monomoy')
            action_at TIMESTAMP,
            response_time_seconds INTEGER,     -- time between sent and action
            pattern_tags TEXT                   -- JSON array of detected patterns
        );
    ''')
    
    # Create patterns table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern_type TEXT NOT NULL,        -- 'auto_trash', 'auto_archive', 'priority_boost', 'priority_lower', 'quiet_sender'
            match_field TEXT NOT NULL,         -- 'sender', 'subject_contains', 'category', 'notification_type'
            match_value TEXT NOT NULL,
            confidence REAL DEFAULT 0.0,      -- 0-1 confidence score
            times_matched INTEGER DEFAULT 0,
            times_confirmed INTEGER DEFAULT 0,
            suggestion_text TEXT,              -- human-readable suggestion
            status TEXT DEFAULT 'suggested',   -- 'suggested', 'approved', 'rejected', 'active'
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    
    # Create daily_stats table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS daily_stats (
            date TEXT PRIMARY KEY,
            heartbeats_run INTEGER DEFAULT 0,
            notifications_sent INTEGER DEFAULT 0,
            actions_taken INTEGER DEFAULT 0,
            actions_ignored INTEGER DEFAULT 0,
            emails_triaged INTEGER DEFAULT 0,
            emails_trashed INTEGER DEFAULT 0,
            emails_archived INTEGER DEFAULT 0,
            emails_left INTEGER DEFAULT 0,
            ideas_reviewed INTEGER DEFAULT 0,
            ideas_to_project INTEGER DEFAULT 0,
            ideas_to_backburner INTEGER DEFAULT 0,
            avg_response_time_seconds REAL,
            estimated_time_saved_minutes REAL,
            token_cost_estimate REAL
        );
    ''')
    
    # Create action_log table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS action_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action_type TEXT NOT NULL,        -- 'email_move', 'message_send', 'file_write', 'api_call', 'cron_execute'
            target TEXT,                       -- what was acted on
            detail TEXT,                       -- specifics
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    
    # Create indexes for better performance
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_notifications_sent_at ON notifications(sent_at);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_notifications_type ON notifications(notification_type);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_patterns_status ON patterns(status);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_action_log_timestamp ON action_log(timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_daily_stats_date ON daily_stats(date);")
    
    conn.commit()
    conn.close()
    
    print(f"✅ Database initialized at: {db_path}")
    return db_path

if __name__ == "__main__":
    init_database()