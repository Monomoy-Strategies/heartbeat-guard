#!/usr/bin/env python3
"""
Heartbeat Analytics Tracker

Tracks notifications, actions, and patterns for the AgentHeartbeat system.
"""

import sqlite3
import os
import json
import datetime
from typing import Optional, Dict, List, Any
from contextlib import contextmanager

# Database path
DB_PATH = os.path.expanduser("~/clawd/data/heartbeat-analytics.db")

@contextmanager
def get_db_connection():
    """Get a database connection with proper cleanup."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Enable dict-like access
    try:
        yield conn
    finally:
        conn.close()

def ensure_db_exists():
    """Ensure the database exists and is initialized."""
    if not os.path.exists(DB_PATH):
        try:
            from . import init_db
        except ImportError:
            import init_db
        init_db.init_database()

def log_notification(notification_type: str, category: Optional[str] = None, 
                    sender: Optional[str] = None, subject: Optional[str] = None,
                    content_summary: Optional[str] = None, urgency: str = 'fyi',
                    channel: str = 'telegram') -> int:
    """
    Log a notification sent to Bill.
    
    Args:
        notification_type: Type of notification ('email_triage', 'idea', 'briefing', etc.)
        category: Subcategory (e.g., 'spam', 'action_required', 'financial')
        sender: Who/what generated the notification
        subject: Brief description
        content_summary: What was in the notification
        urgency: Level ('fyi', 'notice', 'alert', 'urgent', 'critical')
        channel: Delivery channel ('telegram', 'email', etc.)
    
    Returns:
        int: The notification ID
    """
    ensure_db_exists()
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO notifications 
            (notification_type, category, sender, subject, content_summary, urgency, channel)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (notification_type, category, sender, subject, content_summary, urgency, channel))
        
        notification_id = cursor.lastrowid
        conn.commit()
        
        # Log the external action
        log_external_action('message_send', channel, f"Notification #{notification_id}: {notification_type}")
        
        return notification_id

def log_action(notification_id: int, action_taken: str, action_detail: Optional[str] = None) -> None:
    """
    Log an action taken on a notification and calculate response time.
    
    Args:
        notification_id: ID of the notification
        action_taken: Action taken ('acted', 'ignored', 'trashed', etc.)
        action_detail: Specific action details (e.g., 'RATE5', 'FOLD_monomoy')
    """
    ensure_db_exists()
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Get the notification to calculate response time
        cursor.execute('SELECT sent_at FROM notifications WHERE id = ?', (notification_id,))
        row = cursor.fetchone()
        
        if not row:
            raise ValueError(f"Notification {notification_id} not found")
        
        sent_at = datetime.datetime.fromisoformat(row['sent_at'])
        action_at = datetime.datetime.now()
        response_time = int((action_at - sent_at).total_seconds())
        
        # Update the notification
        cursor.execute('''
            UPDATE notifications 
            SET action_taken = ?, action_detail = ?, action_at = ?, response_time_seconds = ?
            WHERE id = ?
        ''', (action_taken, action_detail, action_at.isoformat(), response_time, notification_id))
        
        conn.commit()

def log_external_action(action_type: str, target: Optional[str] = None, detail: Optional[str] = None) -> None:
    """
    Log an external action taken by Jasper.
    
    Args:
        action_type: Type of action ('email_move', 'message_send', 'file_write', etc.)
        target: What was acted on
        detail: Action specifics
    """
    ensure_db_exists()
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO action_log (action_type, target, detail)
            VALUES (?, ?, ?)
        ''', (action_type, target, detail))
        conn.commit()

def update_daily_stats(date: str) -> None:
    """
    Recalculate daily statistics for a given date.
    
    Args:
        date: Date string in YYYY-MM-DD format
    """
    ensure_db_exists()
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Calculate stats for the day
        start_date = f"{date} 00:00:00"
        end_date = f"{date} 23:59:59"
        
        # Notification stats
        cursor.execute('''
            SELECT 
                COUNT(*) as notifications_sent,
                COUNT(CASE WHEN action_taken IS NOT NULL THEN 1 END) as actions_taken,
                COUNT(CASE WHEN action_taken = 'ignored' THEN 1 END) as actions_ignored,
                AVG(CASE WHEN response_time_seconds IS NOT NULL THEN response_time_seconds END) as avg_response_time
            FROM notifications 
            WHERE sent_at BETWEEN ? AND ?
        ''', (start_date, end_date))
        
        stats = cursor.fetchone()
        
        # Email triage specific stats
        cursor.execute('''
            SELECT 
                COUNT(CASE WHEN action_taken = 'trashed' THEN 1 END) as emails_trashed,
                COUNT(CASE WHEN action_taken = 'archived' THEN 1 END) as emails_archived,
                COUNT(CASE WHEN action_taken = 'left' THEN 1 END) as emails_left
            FROM notifications 
            WHERE notification_type = 'email_triage' AND sent_at BETWEEN ? AND ?
        ''', (start_date, end_date))
        
        email_stats = cursor.fetchone()
        
        # Idea stats
        cursor.execute('''
            SELECT 
                COUNT(*) as ideas_reviewed,
                COUNT(CASE WHEN action_taken = 'project' THEN 1 END) as ideas_to_project,
                COUNT(CASE WHEN action_taken = 'backburner' THEN 1 END) as ideas_to_backburner
            FROM notifications 
            WHERE notification_type = 'idea' AND sent_at BETWEEN ? AND ?
        ''', (start_date, end_date))
        
        idea_stats = cursor.fetchone()
        
        # Heartbeat count from action_log
        cursor.execute('''
            SELECT COUNT(*) as heartbeats_run
            FROM action_log 
            WHERE action_type = 'cron_execute' AND target LIKE '%heartbeat%' 
            AND timestamp BETWEEN ? AND ?
        ''', (start_date, end_date))
        
        heartbeat_stats = cursor.fetchone()
        
        # Calculate estimated time saved (rough heuristic)
        actions_taken = stats['actions_taken'] or 0
        avg_response_time = stats['avg_response_time'] or 0
        estimated_time_saved = (actions_taken * 2.5)  # Assume 2.5 minutes saved per action
        
        # Estimate token cost (very rough)
        token_cost_estimate = stats['notifications_sent'] * 0.002  # $0.002 per notification estimate
        
        # Upsert daily stats
        cursor.execute('''
            INSERT OR REPLACE INTO daily_stats (
                date, heartbeats_run, notifications_sent, actions_taken, actions_ignored,
                emails_triaged, emails_trashed, emails_archived, emails_left,
                ideas_reviewed, ideas_to_project, ideas_to_backburner,
                avg_response_time_seconds, estimated_time_saved_minutes, token_cost_estimate
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            date,
            heartbeat_stats['heartbeats_run'] or 0,
            stats['notifications_sent'] or 0,
            actions_taken,
            stats['actions_ignored'] or 0,
            email_stats['emails_trashed'] + email_stats['emails_archived'] + email_stats['emails_left'],
            email_stats['emails_trashed'] or 0,
            email_stats['emails_archived'] or 0,
            email_stats['emails_left'] or 0,
            idea_stats['ideas_reviewed'] or 0,
            idea_stats['ideas_to_project'] or 0,
            idea_stats['ideas_to_backburner'] or 0,
            avg_response_time,
            estimated_time_saved,
            token_cost_estimate
        ))
        
        conn.commit()

def analyze_patterns() -> List[Dict[str, Any]]:
    """
    Analyze recent notifications for patterns and create suggestions.
    
    Returns:
        List of new pattern suggestions
    """
    ensure_db_exists()
    
    new_patterns = []
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Look at last 30 days of data
        cutoff_date = (datetime.datetime.now() - datetime.timedelta(days=30)).isoformat()
        
        # Pattern 1: Senders consistently trashed
        cursor.execute('''
            SELECT sender, COUNT(*) as trash_count
            FROM notifications 
            WHERE action_taken = 'trashed' 
            AND sender IS NOT NULL 
            AND sent_at > ?
            GROUP BY sender 
            HAVING trash_count >= 3
        ''', (cutoff_date,))
        
        for row in cursor.fetchall():
            sender = row['sender']
            count = row['trash_count']
            
            # Check if we already have this pattern
            cursor.execute('''
                SELECT id FROM patterns 
                WHERE pattern_type = 'auto_trash' 
                AND match_field = 'sender' 
                AND match_value = ?
            ''', (sender,))
            
            if not cursor.fetchone():
                suggestion = {
                    'pattern_type': 'auto_trash',
                    'match_field': 'sender',
                    'match_value': sender,
                    'confidence': min(0.9, count / 5.0),
                    'suggestion_text': f"Auto-trash emails from '{sender}' (trashed {count} times)",
                    'times_matched': count
                }
                new_patterns.append(suggestion)
        
        # Pattern 2: Categories consistently ignored
        cursor.execute('''
            SELECT category, 
                   COUNT(*) as total_count,
                   COUNT(CASE WHEN action_taken = 'ignored' THEN 1 END) as ignored_count
            FROM notifications 
            WHERE category IS NOT NULL 
            AND sent_at > ?
            GROUP BY category 
            HAVING total_count >= 5 AND (ignored_count * 1.0 / total_count) >= 0.7
        ''', (cutoff_date,))
        
        for row in cursor.fetchall():
            category = row['category']
            ignored_ratio = row['ignored_count'] / row['total_count']
            
            cursor.execute('''
                SELECT id FROM patterns 
                WHERE pattern_type = 'priority_lower' 
                AND match_field = 'category' 
                AND match_value = ?
            ''', (category,))
            
            if not cursor.fetchone():
                suggestion = {
                    'pattern_type': 'priority_lower',
                    'match_field': 'category',
                    'match_value': category,
                    'confidence': ignored_ratio,
                    'suggestion_text': f"Lower priority for category '{category}' (ignored {ignored_ratio:.0%} of time)",
                    'times_matched': row['total_count']
                }
                new_patterns.append(suggestion)
        
        # Pattern 3: Quick actions on certain types
        cursor.execute('''
            SELECT notification_type, AVG(response_time_seconds) as avg_response
            FROM notifications 
            WHERE action_taken IS NOT NULL 
            AND action_taken != 'ignored'
            AND response_time_seconds IS NOT NULL
            AND sent_at > ?
            GROUP BY notification_type
            HAVING COUNT(*) >= 3 AND avg_response <= 300
        ''', (cutoff_date,))
        
        for row in cursor.fetchall():
            notification_type = row['notification_type']
            avg_response = row['avg_response']
            
            cursor.execute('''
                SELECT id FROM patterns 
                WHERE pattern_type = 'priority_boost' 
                AND match_field = 'notification_type' 
                AND match_value = ?
            ''', (notification_type,))
            
            if not cursor.fetchone():
                suggestion = {
                    'pattern_type': 'priority_boost',
                    'match_field': 'notification_type',
                    'match_value': notification_type,
                    'confidence': max(0.6, 1.0 - (avg_response / 300)),
                    'suggestion_text': f"Boost priority for '{notification_type}' (avg response: {avg_response:.0f}s)",
                    'times_matched': 1
                }
                new_patterns.append(suggestion)
        
        # Insert new patterns
        for pattern in new_patterns:
            cursor.execute('''
                INSERT INTO patterns (
                    pattern_type, match_field, match_value, confidence,
                    times_matched, suggestion_text
                ) VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                pattern['pattern_type'], pattern['match_field'], pattern['match_value'],
                pattern['confidence'], pattern['times_matched'], pattern['suggestion_text']
            ))
        
        conn.commit()
    
    return new_patterns

def get_suggestions() -> List[Dict[str, Any]]:
    """
    Get pending pattern suggestions for Bill to approve/reject.
    
    Returns:
        List of pending suggestions
    """
    ensure_db_exists()
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM patterns 
            WHERE status = 'suggested'
            ORDER BY confidence DESC, created_at DESC
        ''')
        
        return [dict(row) for row in cursor.fetchall()]

def get_daily_report(date: str) -> str:
    """
    Get formatted daily analytics report.
    
    Args:
        date: Date string in YYYY-MM-DD format
    
    Returns:
        Formatted report string
    """
    ensure_db_exists()
    
    # Update stats first
    update_daily_stats(date)
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM daily_stats WHERE date = ?', (date,))
        stats = cursor.fetchone()
        
        if not stats:
            return f"📊 **Daily Report - {date}**\n\nNo data available for this date."
        
        report = f"""📊 **Daily Report - {date}**

🤖 **System Activity:**
• Heartbeats: {stats['heartbeats_run']}
• Notifications sent: {stats['notifications_sent']}
• Actions taken: {stats['actions_taken']}
• Actions ignored: {stats['actions_ignored']}

📧 **Email Triage:**
• Total triaged: {stats['emails_triaged']}
• Trashed: {stats['emails_trashed']}
• Archived: {stats['emails_archived']}
• Left in inbox: {stats['emails_left']}

💡 **Ideas Pipeline:**
• Ideas reviewed: {stats['ideas_reviewed']}
• Moved to projects: {stats['ideas_to_project']}
• Moved to backburner: {stats['ideas_to_backburner']}

⚡ **Performance:**
• Avg response time: {stats['avg_response_time_seconds']:.1f}s
• Est. time saved: {stats['estimated_time_saved_minutes']:.1f} minutes
• Est. token cost: ${stats['token_cost_estimate']:.3f}
"""
        
        return report

def get_weekly_report() -> str:
    """
    Get formatted weekly summary report.
    
    Returns:
        Formatted weekly report string
    """
    ensure_db_exists()
    
    # Get last 7 days
    end_date = datetime.datetime.now()
    start_date = end_date - datetime.timedelta(days=7)
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Get weekly totals
        cursor.execute('''
            SELECT 
                SUM(notifications_sent) as total_notifications,
                SUM(actions_taken) as total_actions,
                SUM(actions_ignored) as total_ignored,
                SUM(emails_trashed) as total_trashed,
                SUM(emails_archived) as total_archived,
                SUM(ideas_to_project) as total_ideas_to_project,
                AVG(avg_response_time_seconds) as avg_response_time,
                SUM(estimated_time_saved_minutes) as total_time_saved,
                SUM(token_cost_estimate) as total_cost
            FROM daily_stats 
            WHERE date BETWEEN ? AND ?
        ''', (start_date.strftime('%Y-%m-%d'), end_date.strftime('%Y-%m-%d')))
        
        stats = cursor.fetchone()
        
        if not stats or not stats['total_notifications']:
            return f"📊 **Weekly Report ({start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')})**\n\nNo data available for this period."
        
        # Get daily breakdown
        cursor.execute('''
            SELECT date, notifications_sent, actions_taken
            FROM daily_stats 
            WHERE date BETWEEN ? AND ?
            ORDER BY date DESC
        ''', (start_date.strftime('%Y-%m-%d'), end_date.strftime('%Y-%m-%d')))
        
        daily_data = cursor.fetchall()
        
        report = f"""📊 **Weekly Report ({start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')})**

📈 **Totals:**
• Notifications: {stats['total_notifications']}
• Actions taken: {stats['total_actions']}
• Response rate: {(stats['total_actions'] / stats['total_notifications'] * 100):.1f}%

📧 **Email Management:**
• Emails trashed: {stats['total_trashed']}
• Emails archived: {stats['total_archived']}

💡 **Innovation:**
• Ideas moved to projects: {stats['total_ideas_to_project']}

⚡ **Efficiency:**
• Avg response time: {stats['avg_response_time']:.1f}s
• Total time saved: {stats['total_time_saved']:.1f} minutes
• Total cost: ${stats['total_cost']:.3f}

📅 **Daily Breakdown:**"""
        
        for day in daily_data:
            if day['notifications_sent']:
                report += f"\n• {day['date']}: {day['notifications_sent']} notifications, {day['actions_taken']} actions"
        
        return report

# Initialize database on import
if __name__ == "__main__":
    ensure_db_exists()
    print("✅ Tracker module initialized")