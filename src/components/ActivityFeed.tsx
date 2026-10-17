import { motion } from 'framer-motion';
import { CheckCircle2, MessageSquare, GitPullRequest, AlertCircle, User } from 'lucide-react';

const activities = [
  {
    id: 1,
    type: 'completed' as const,
    user: 'Alex Chen',
    action: 'completed task',
    target: 'Design new landing page mockups',
    time: '2 minutes ago',
    icon: CheckCircle2,
    color: 'text-emerald-400',
    bgColor: 'bg-emerald-400/10',
  },
  {
    id: 2,
    type: 'comment' as const,
    user: 'Sarah Miller',
    action: 'commented on',
    target: 'API documentation review',
    time: '15 minutes ago',
    icon: MessageSquare,
    color: 'text-blue-400',
    bgColor: 'bg-blue-400/10',
  },
  {
    id: 3,
    type: 'pr' as const,
    user: 'James Wilson',
    action: 'opened a pull request',
    target: 'feat: implement OAuth2 flow',
    time: '1 hour ago',
    icon: GitPullRequest,
    color: 'text-violet-400',
    bgColor: 'bg-violet-400/10',
  },
  {
    id: 4,
    type: 'alert' as const,
    user: 'System',
    action: 'flagged issue',
    target: 'Build pipeline failing on main',
    time: '2 hours ago',
    icon: AlertCircle,
    color: 'text-amber-400',
    bgColor: 'bg-amber-400/10',
  },
  {
    id: 5,
    type: 'completed' as const,
    user: 'Emily Davis',
    action: 'completed task',
    target: 'User testing session notes',
    time: '3 hours ago',
    icon: CheckCircle2,
    color: 'text-emerald-400',
    bgColor: 'bg-emerald-400/10',
  },
  {
    id: 6,
    type: 'comment' as const,
    user: 'Alex Chen',
    action: 'commented on',
    target: 'Sprint planning document',
    time: '4 hours ago',
    icon: MessageSquare,
    color: 'text-blue-400',
    bgColor: 'bg-blue-400/10',
  },
];

export default function ActivityFeed() {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <h2 className="font-semibold text-lg">Recent Activity</h2>
        <button className="text-sm text-violet-400 hover:text-violet-300 transition-colors">
          View all
        </button>
      </div>
      <div className="space-y-1">
        {activities.map((activity, index) => (
          <motion.div
            key={activity.id}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: index * 0.05 }}
            className="flex items-start gap-3 p-3 rounded-lg hover:bg-gray-800/50 transition-colors"
          >
            <div className={`w-8 h-8 rounded-full ${activity.bgColor} flex items-center justify-center flex-shrink-0`}>
              <activity.icon className={`w-4 h-4 ${activity.color}`} />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm">
                <span className="font-medium text-white">{activity.user}</span>
                <span className="text-gray-400"> {activity.action} </span>
                <span className="text-gray-300 font-medium">{activity.target}</span>
              </p>
              <p className="text-xs text-gray-500 mt-1">{activity.time}</p>
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );
}
