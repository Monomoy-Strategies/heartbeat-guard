#!/usr/bin/env python3
"""
Heartbeat Analytics Report CLI

Command-line tool for generating reports from the heartbeat analytics system.
"""

import argparse
import sys
import datetime
import os

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from . import tracker
except ImportError:
    import tracker

def format_for_telegram(text: str) -> str:
    """Format text for Telegram delivery with proper markdown."""
    # Ensure proper spacing and formatting
    return text.strip()

def daily_report(date: str = None) -> str:
    """Generate daily report."""
    if not date:
        date = datetime.datetime.now().strftime('%Y-%m-%d')
    
    try:
        # Validate date format
        datetime.datetime.strptime(date, '%Y-%m-%d')
    except ValueError:
        return f"❌ Invalid date format. Use YYYY-MM-DD (got: {date})"
    
    try:
        report = tracker.get_daily_report(date)
        return format_for_telegram(report)
    except Exception as e:
        return f"❌ Error generating daily report: {str(e)}"

def weekly_report() -> str:
    """Generate weekly report."""
    try:
        report = tracker.get_weekly_report()
        return format_for_telegram(report)
    except Exception as e:
        return f"❌ Error generating weekly report: {str(e)}"

def suggestions_report() -> str:
    """Generate suggestions report."""
    try:
        suggestions = tracker.get_suggestions()
        
        if not suggestions:
            return "💡 **Pattern Suggestions**\n\nNo pending suggestions at this time."
        
        report = "💡 **Pattern Suggestions**\n\nThe following patterns have been detected:\n"
        
        for i, suggestion in enumerate(suggestions, 1):
            confidence_percent = int(suggestion['confidence'] * 100)
            report += f"\n**{i}. {suggestion['suggestion_text']}**"
            report += f"\n• Type: {suggestion['pattern_type']}"
            report += f"\n• Confidence: {confidence_percent}%"
            report += f"\n• Matches: {suggestion['times_matched']}"
            if suggestion['match_field'] and suggestion['match_value']:
                report += f"\n• Rule: {suggestion['match_field']} = '{suggestion['match_value']}'"
            report += "\n"
        
        report += "\n💬 React to approve/reject these suggestions!"
        
        return format_for_telegram(report)
    except Exception as e:
        return f"❌ Error generating suggestions report: {str(e)}"

def stats_summary() -> str:
    """Generate quick stats summary for the last 7 days."""
    try:
        # Get basic stats from the last week
        end_date = datetime.datetime.now()
        dates = []
        for i in range(7):
            date = (end_date - datetime.timedelta(days=i)).strftime('%Y-%m-%d')
            dates.append(date)
            # Ensure daily stats are updated
            tracker.update_daily_stats(date)
        
        # Run pattern analysis
        new_patterns = tracker.analyze_patterns()
        pattern_count = len(tracker.get_suggestions())
        
        report = f"""🤖 **Heartbeat Analytics Summary**

📊 **Last 7 Days Updated**
📈 **Pattern Analysis Complete**
• New patterns detected: {len(new_patterns)}
• Total pending suggestions: {pattern_count}

🔍 **Available Reports:**
• Daily: `python3 report.py --daily [YYYY-MM-DD]`
• Weekly: `python3 report.py --weekly`
• Suggestions: `python3 report.py --suggestions`

Database: ~/clawd/data/heartbeat-analytics.db"""

        return format_for_telegram(report)
    except Exception as e:
        return f"❌ Error generating stats summary: {str(e)}"

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Generate heartbeat analytics reports',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 report.py --daily                    # Today's report
  python3 report.py --daily 2026-02-07         # Specific date
  python3 report.py --weekly                   # Last 7 days
  python3 report.py --suggestions               # Pattern suggestions
  python3 report.py --summary                  # Quick overview
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--daily', nargs='?', const='', 
                      help='Daily report (optional date: YYYY-MM-DD)')
    group.add_argument('--weekly', action='store_true',
                      help='Weekly summary report')
    group.add_argument('--suggestions', action='store_true',
                      help='Pattern suggestions report')
    group.add_argument('--summary', action='store_true',
                      help='Quick stats summary')
    
    args = parser.parse_args()
    
    try:
        if args.daily is not None:
            date = args.daily if args.daily else None
            output = daily_report(date)
        elif args.weekly:
            output = weekly_report()
        elif args.suggestions:
            output = suggestions_report()
        elif args.summary:
            output = stats_summary()
        else:
            parser.print_help()
            return 1
        
        print(output)
        return 0
        
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}", file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())