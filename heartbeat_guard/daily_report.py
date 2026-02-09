#!/usr/bin/env python3
"""
Daily Analytics Report Generator

Generates a comprehensive daily analytics report formatted for Telegram delivery.
Integrates with all the hook modules to provide insights across all systems.
"""

import sys
import os
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tracker import get_daily_report, get_suggestions, update_daily_stats
from hooks import (
    get_email_triage_stats, get_idea_pipeline_stats, get_briefing_stats,
    get_heartbeat_stats, get_message_stats, get_response_patterns,
    get_heartbeat_performance_trends, get_briefing_optimization_suggestions
)


def generate_daily_analytics_report(date: Optional[str] = None, include_trends: bool = True, 
                                  include_suggestions: bool = True) -> str:
    """
    Generate a comprehensive daily analytics report.
    
    Args:
        date: Date in YYYY-MM-DD format. If None, uses today.
        include_trends: Whether to include trend analysis
        include_suggestions: Whether to include AI suggestions
    
    Returns:
        str: Formatted report for Telegram delivery
    """
    if date is None:
        date = datetime.now().strftime('%Y-%m-%d')
    
    try:
        # Update daily stats first
        update_daily_stats(date)
        
        # Collect data from all systems
        email_stats = get_email_triage_stats(date)
        idea_stats = get_idea_pipeline_stats(date) 
        briefing_stats = get_briefing_stats(date)
        heartbeat_stats = get_heartbeat_stats(date)
        message_stats = get_message_stats(date)
        
        # Start building the report
        report_parts = []
        
        # Header
        report_parts.append(f"📊 **Daily Analytics Report**")
        report_parts.append(f"📅 {_format_date(date)}")
        report_parts.append("")
        
        # System Overview
        system_overview = _generate_system_overview(heartbeat_stats, message_stats, date)
        if system_overview:
            report_parts.append(system_overview)
            report_parts.append("")
        
        # Email Triage Section
        email_section = _generate_email_section(email_stats)
        if email_section:
            report_parts.append(email_section)
            report_parts.append("")
        
        # Ideas Pipeline Section  
        ideas_section = _generate_ideas_section(idea_stats)
        if ideas_section:
            report_parts.append(ideas_section)
            report_parts.append("")
        
        # Briefing Section
        briefing_section = _generate_briefing_section(briefing_stats)
        if briefing_section:
            report_parts.append(briefing_section)
            report_parts.append("")
        
        # Communication Section
        comm_section = _generate_communication_section(message_stats)
        if comm_section:
            report_parts.append(comm_section)
            report_parts.append("")
        
        # Performance Metrics
        performance_section = _generate_performance_section(email_stats, idea_stats, message_stats)
        if performance_section:
            report_parts.append(performance_section)
            report_parts.append("")
        
        # Time Saved Estimation
        time_saved_section = _generate_time_saved_section(email_stats, idea_stats, heartbeat_stats)
        if time_saved_section:
            report_parts.append(time_saved_section)
            report_parts.append("")
        
        # Trends (if requested)
        if include_trends:
            trends_section = _generate_trends_section(date)
            if trends_section:
                report_parts.append(trends_section)
                report_parts.append("")
        
        # AI Suggestions (if requested)
        if include_suggestions:
            suggestions_section = _generate_suggestions_section()
            if suggestions_section:
                report_parts.append(suggestions_section)
                report_parts.append("")
        
        # Footer with timestamp
        report_parts.append(f"🕐 Generated: {datetime.now().strftime('%H:%M:%S UTC')}")
        
        return "\n".join(report_parts)
        
    except Exception as e:
        error_report = f"❌ **Daily Analytics Report Error**\n📅 {date}\n\nError generating report: {str(e)}\n\n🕐 {datetime.now().strftime('%H:%M:%S UTC')}"
        print(f"Error generating daily report: {e}")
        return error_report


def _format_date(date_str: str) -> str:
    """Format date string for display."""
    try:
        dt = datetime.strptime(date_str, '%Y-%m-%d')
        return dt.strftime('%A, %B %d, %Y')
    except:
        return date_str


def _generate_system_overview(heartbeat_stats: Dict, message_stats: Dict, date: str) -> str:
    """Generate system overview section."""
    try:
        heartbeats = heartbeat_stats.get('heartbeats_run', 0)
        total_messages = message_stats.get('total_messages', 0)
        response_rate = message_stats.get('overall_response_rate', 0)
        
        overview = "🤖 **System Overview**"
        overview += f"\n• Heartbeat cycles: {heartbeats}"
        overview += f"\n• Messages sent: {total_messages}"
        
        if total_messages > 0:
            overview += f"\n• Response rate: {response_rate:.0%}"
        
        # Add system health indicator
        if heartbeats >= 24:  # Expected ~hourly
            overview += "\n• Status: ✅ Normal operation"
        elif heartbeats >= 12:
            overview += "\n• Status: ⚠️ Reduced activity"
        else:
            overview += "\n• Status: 🔴 Low activity"
        
        return overview
    except Exception as e:
        print(f"Error generating system overview: {e}")
        return ""


def _generate_email_section(email_stats: Dict) -> str:
    """Generate email triage section."""
    if not email_stats:
        return ""
    
    try:
        trashed = email_stats.get('trashed', 0)
        archived = email_stats.get('archived', 0) 
        left = email_stats.get('left', 0)
        moved_to_folder = email_stats.get('moved_to_folder', 0)
        
        total_triaged = trashed + archived + left + moved_to_folder
        
        if total_triaged == 0:
            return ""
        
        section = "📧 **Email Triage**"
        section += f"\n• Total processed: {total_triaged}"
        section += f"\n• 🗑️ Trashed: {trashed}"
        section += f"\n• 📦 Archived: {archived}"
        section += f"\n• ✅ Left in inbox: {left}"
        
        if moved_to_folder > 0:
            section += f"\n• 📁 Moved to folders: {moved_to_folder}"
        
        # Calculate efficiency percentage
        action_taken = trashed + archived + moved_to_folder
        if total_triaged > 0:
            efficiency = (action_taken / total_triaged) * 100
            section += f"\n• Efficiency: {efficiency:.0f}% (actions taken)"
        
        return section
    except Exception as e:
        print(f"Error generating email section: {e}")
        return ""


def _generate_ideas_section(idea_stats: Dict) -> str:
    """Generate ideas pipeline section."""
    if not idea_stats:
        return ""
    
    try:
        moved_to_project = sum(stats.get('count', 0) for action, stats in idea_stats.items() 
                              if isinstance(stats, dict) and action == 'moved_to_project')
        moved_to_backburner = sum(stats.get('count', 0) for action, stats in idea_stats.items()
                                 if isinstance(stats, dict) and action == 'moved_to_backburner') 
        archived = sum(stats.get('count', 0) for action, stats in idea_stats.items()
                      if isinstance(stats, dict) and action == 'archived')
        
        # Count ratings
        ratings = idea_stats.get('ratings', {})
        total_rated = sum(ratings.values()) if ratings else 0
        
        total_reviewed = moved_to_project + moved_to_backburner + archived + total_rated
        
        if total_reviewed == 0:
            return ""
        
        section = "💡 **Ideas Pipeline**"
        section += f"\n• Total reviewed: {total_reviewed}"
        section += f"\n• ▶️ To projects: {moved_to_project}"
        section += f"\n• 💭 To backburner: {moved_to_backburner}"
        section += f"\n• 📚 Archived: {archived}"
        
        if total_rated > 0:
            section += f"\n• ⭐ Rated: {total_rated}"
            
            # Show rating breakdown
            if ratings:
                top_rating = max(ratings.keys(), key=lambda k: int(k.split('_')[-1]))
                section += f" (best: {top_rating.replace('rate_', '')}⭐)"
        
        return section
    except Exception as e:
        print(f"Error generating ideas section: {e}")
        return ""


def _generate_briefing_section(briefing_stats: Dict) -> str:
    """Generate briefing section."""
    if not briefing_stats:
        return ""
    
    try:
        briefings_sent = briefing_stats.get('briefings_sent', 0)
        engaged_count = briefing_stats.get('engaged_count', 0)
        engagement_rate = briefing_stats.get('engagement_rate', 0)
        
        if briefings_sent == 0:
            return ""
        
        section = "📰 **Morning Briefing**"
        section += f"\n• Briefings delivered: {briefings_sent}"
        
        if engaged_count > 0:
            section += f"\n• Engagement: {engagement_rate:.0%} ({engaged_count}/{briefings_sent})"
        else:
            section += f"\n• Engagement: No responses yet"
        
        # Show popular sections if available
        sections = briefing_stats.get('sections_included', {})
        if sections:
            top_sections = sorted(sections.items(), key=lambda x: x[1], reverse=True)[:3]
            section += f"\n• Top sections: {', '.join([s[0] for s in top_sections])}"
        
        return section
    except Exception as e:
        print(f"Error generating briefing section: {e}")
        return ""


def _generate_communication_section(message_stats: Dict) -> str:
    """Generate communication section."""
    if not message_stats:
        return ""
    
    try:
        total_messages = message_stats.get('total_messages', 0)
        total_responses = message_stats.get('total_responses', 0)
        response_rate = message_stats.get('overall_response_rate', 0)
        avg_response_time = message_stats.get('overall_avg_response_time_seconds', 0)
        
        if total_messages == 0:
            return ""
        
        section = "💬 **Communication**"
        section += f"\n• Messages sent: {total_messages}"
        section += f"\n• Responses received: {total_responses}"
        section += f"\n• Response rate: {response_rate:.0%}"
        
        if avg_response_time > 0:
            if avg_response_time < 60:
                time_str = f"{avg_response_time:.0f}s"
            elif avg_response_time < 3600:
                time_str = f"{avg_response_time/60:.1f}m"
            else:
                time_str = f"{avg_response_time/3600:.1f}h"
            section += f"\n• Avg response time: {time_str}"
        
        # Show urgency breakdown if available
        urgency_stats = message_stats.get('urgency_breakdown', {})
        if urgency_stats:
            urgent_count = urgency_stats.get('urgent', {}).get('count', 0) + urgency_stats.get('critical', {}).get('count', 0)
            if urgent_count > 0:
                section += f"\n• Urgent messages: {urgent_count}"
        
        return section
    except Exception as e:
        print(f"Error generating communication section: {e}")
        return ""


def _generate_performance_section(email_stats: Dict, idea_stats: Dict, message_stats: Dict) -> str:
    """Generate performance metrics section."""
    try:
        section = "⚡ **Performance Metrics**"
        
        # Response time analysis
        avg_times = []
        
        # Add message response time
        msg_time = message_stats.get('overall_avg_response_time_seconds', 0)
        if msg_time > 0:
            avg_times.append(msg_time)
        
        # Add idea response times
        for action, stats in idea_stats.items():
            if isinstance(stats, dict) and 'avg_response_time_seconds' in stats:
                time_val = stats['avg_response_time_seconds']
                if time_val > 0:
                    avg_times.append(time_val)
        
        if avg_times:
            overall_avg = sum(avg_times) / len(avg_times)
            if overall_avg < 300:  # Less than 5 minutes
                section += f"\n• 🚀 Quick responses (avg {overall_avg/60:.1f}m)"
            elif overall_avg < 1800:  # Less than 30 minutes
                section += f"\n• ✅ Good response time (avg {overall_avg/60:.1f}m)"
            else:
                section += f"\n• ⏳ Slower responses (avg {overall_avg/3600:.1f}h)"
        
        # Action efficiency
        total_notifications = (
            sum(email_stats.values()) + 
            sum(stats.get('count', 0) if isinstance(stats, dict) else stats 
                for stats in idea_stats.values()) +
            message_stats.get('total_messages', 0)
        )
        
        total_actions = (
            sum(email_stats.get(k, 0) for k in ['trashed', 'archived', 'moved_to_folder']) +
            sum(stats.get('count', 0) if isinstance(stats, dict) else 0
                for k, stats in idea_stats.items() if k != 'ratings') +
            message_stats.get('total_responses', 0)
        )
        
        if total_notifications > 0:
            efficiency = (total_actions / total_notifications) * 100
            section += f"\n• Action rate: {efficiency:.0f}% ({total_actions}/{total_notifications})"
        
        return section if len(section.split('\n')) > 1 else ""
        
    except Exception as e:
        print(f"Error generating performance section: {e}")
        return ""


def _generate_time_saved_section(email_stats: Dict, idea_stats: Dict, heartbeat_stats: Dict) -> str:
    """Generate estimated time saved section."""
    try:
        total_time_saved = 0
        
        # Email triage time savings (2 minutes per email processed)
        emails_processed = sum(email_stats.values())
        email_time_saved = emails_processed * 2
        total_time_saved += email_time_saved
        
        # Ideas processing time savings (3 minutes per idea reviewed)
        ideas_processed = sum(stats.get('count', 0) if isinstance(stats, dict) else stats
                             for stats in idea_stats.values())
        idea_time_saved = ideas_processed * 3  
        total_time_saved += idea_time_saved
        
        # Heartbeat automation time savings (5 minutes per cycle)
        heartbeats = heartbeat_stats.get('heartbeats_run', 0)
        heartbeat_time_saved = heartbeats * 5
        total_time_saved += heartbeat_time_saved
        
        if total_time_saved == 0:
            return ""
        
        section = "⏰ **Estimated Time Saved**"
        
        if email_time_saved > 0:
            section += f"\n• Email triage: {email_time_saved} minutes"
        if idea_time_saved > 0:
            section += f"\n• Ideas processing: {idea_time_saved} minutes"
        if heartbeat_time_saved > 0:
            section += f"\n• System monitoring: {heartbeat_time_saved} minutes"
        
        section += f"\n• **Total: {total_time_saved} minutes ({total_time_saved/60:.1f} hours)**"
        
        return section
        
    except Exception as e:
        print(f"Error generating time saved section: {e}")
        return ""


def _generate_trends_section(date: str) -> str:
    """Generate trends analysis section."""
    try:
        # Get performance trends
        heartbeat_trends = get_heartbeat_performance_trends()
        response_patterns = get_response_patterns()
        
        if not heartbeat_trends and not response_patterns:
            return ""
        
        section = "📈 **Trends & Patterns**"
        
        # Heartbeat trends
        if heartbeat_trends:
            daily_counts = heartbeat_trends.get('daily_heartbeat_counts', {})
            if len(daily_counts) >= 2:
                dates = sorted(daily_counts.keys())
                recent_avg = sum(daily_counts[d] for d in dates[-3:]) / min(3, len(dates))
                section += f"\n• Recent heartbeat avg: {recent_avg:.1f}/day"
        
        # Response patterns
        if response_patterns:
            high_engagement = [p for p in response_patterns 
                              if p.get('type') == 'high_engagement_category']
            if high_engagement:
                categories = [p['category'] for p in high_engagement[:2]]
                section += f"\n• High engagement: {', '.join(categories)}"
        
        return section if len(section.split('\n')) > 1 else ""
        
    except Exception as e:
        print(f"Error generating trends section: {e}")
        return ""


def _generate_suggestions_section() -> str:
    """Generate AI suggestions section."""
    try:
        suggestions = get_suggestions()
        briefing_suggestions = get_briefing_optimization_suggestions()
        
        all_suggestions = suggestions + briefing_suggestions
        
        if not all_suggestions:
            return ""
        
        section = "🤖 **AI Suggestions**"
        
        # Show top 3 suggestions
        for i, suggestion in enumerate(all_suggestions[:3]):
            if isinstance(suggestion, dict):
                text = suggestion.get('suggestion_text', str(suggestion))
                confidence = suggestion.get('confidence', 0)
                section += f"\n• {text}"
                if confidence > 0:
                    section += f" (confidence: {confidence:.0%})"
        
        if len(all_suggestions) > 3:
            section += f"\n• ...and {len(all_suggestions) - 3} more suggestions"
        
        return section
        
    except Exception as e:
        print(f"Error generating suggestions section: {e}")
        return ""


def generate_weekly_summary() -> str:
    """Generate a weekly summary report."""
    try:
        from tracker import get_weekly_report
        
        # Get base weekly report
        base_report = get_weekly_report()
        
        # Add hook-specific weekly insights
        end_date = datetime.now()
        start_date = end_date - timedelta(days=7)
        
        weekly_insights = []
        
        # Analyze weekly patterns from response patterns
        patterns = get_response_patterns()
        optimization_suggestions = get_briefing_optimization_suggestions()
        
        if patterns:
            weekly_insights.append("📊 **Weekly Insights**")
            for pattern in patterns[:2]:
                if 'insight' in pattern:
                    weekly_insights.append(f"• {pattern['insight']}")
        
        if optimization_suggestions:
            weekly_insights.append("\n🔧 **Optimization Opportunities**")
            for suggestion in optimization_suggestions[:2]:
                if 'recommendation' in suggestion:
                    weekly_insights.append(f"• {suggestion['recommendation']}")
        
        # Combine reports
        if weekly_insights:
            return base_report + "\n\n" + "\n".join(weekly_insights)
        else:
            return base_report
            
    except Exception as e:
        print(f"Error generating weekly summary: {e}")
        return f"❌ Error generating weekly summary: {str(e)}"


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate daily analytics report")
    parser.add_argument('--date', help='Date in YYYY-MM-DD format (default: today)')
    parser.add_argument('--no-trends', action='store_true', help='Exclude trend analysis')
    parser.add_argument('--no-suggestions', action='store_true', help='Exclude AI suggestions')
    parser.add_argument('--weekly', action='store_true', help='Generate weekly summary instead')
    parser.add_argument('--output', help='Output file path')
    
    args = parser.parse_args()
    
    try:
        if args.weekly:
            report = generate_weekly_summary()
        else:
            report = generate_daily_analytics_report(
                date=args.date,
                include_trends=not args.no_trends,
                include_suggestions=not args.no_suggestions
            )
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"Report written to {args.output}")
        else:
            print(report)
            
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)