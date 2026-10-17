import { motion } from 'framer-motion';
import { Plus, Calendar, Clock, Star, ArrowRight } from 'lucide-react';

const upcomingTasks = [
  { id: 1, title: 'Team standup meeting', time: '9:00 AM', priority: 'medium' },
  { id: 2, title: 'Code review: auth module', time: '11:00 AM', priority: 'high' },
  { id: 3, title: 'Deploy staging build', time: '2:00 PM', priority: 'low' },
  { id: 4, title: 'Client presentation prep', time: '4:00 PM', priority: 'high' },
];

const shortcuts = [
  { label: 'New Project', icon: Plus, color: 'from-violet-500 to-purple-600' },
  { label: 'Schedule', icon: Calendar, color: 'from-blue-500 to-indigo-600' },
  { label: 'Time Log', icon: Clock, color: 'from-emerald-500 to-green-600' },
  { label: 'Favorites', icon: Star, color: 'from-amber-500 to-orange-600' },
];

export default function QuickActions() {
  return (
    <div className="space-y-4">
      {/* Quick Shortcuts */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
        <h2 className="font-semibold text-lg mb-4">Quick Actions</h2>
        <div className="grid grid-cols-2 gap-3">
          {shortcuts.map((shortcut, index) => (
            <motion.button
              key={shortcut.label}
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: index * 0.1 }}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="flex flex-col items-center gap-2 p-4 rounded-lg bg-gray-800 border border-gray-700 hover:border-gray-600 transition-colors"
            >
              <div className={`w-10 h-10 rounded-lg bg-gradient-to-br ${shortcut.color} flex items-center justify-center`}>
                <shortcut.icon className="w-5 h-5 text-white" />
              </div>
              <span className="text-xs text-gray-300">{shortcut.label}</span>
            </motion.button>
          ))}
        </div>
      </div>

      {/* Upcoming Tasks */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-semibold text-lg">Upcoming</h2>
          <button className="text-sm text-violet-400 hover:text-violet-300 transition-colors flex items-center gap-1">
            See all <ArrowRight className="w-3 h-3" />
          </button>
        </div>
        <div className="space-y-3">
          {upcomingTasks.map((task, index) => (
            <motion.div
              key={task.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              className="flex items-center gap-3 p-2 rounded-lg hover:bg-gray-800/50 transition-colors cursor-pointer"
            >
              <div className={`w-2 h-2 rounded-full flex-shrink-0 ${
                task.priority === 'high' ? 'bg-red-400' : 
                task.priority === 'medium' ? 'bg-amber-400' : 'bg-gray-400'
              }`}></div>
              <div className="flex-1 min-w-0">
                <p className="text-sm text-white truncate">{task.title}</p>
                <p className="text-xs text-gray-500">{task.time}</p>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </div>
  );
}
