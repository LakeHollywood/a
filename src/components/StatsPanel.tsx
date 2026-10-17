import { motion } from 'framer-motion';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line, AreaChart, Area } from 'recharts';

const weeklyData = [
  { name: 'Mon', tasks: 8, hours: 6.5 },
  { name: 'Tue', tasks: 12, hours: 8 },
  { name: 'Wed', tasks: 6, hours: 4.5 },
  { name: 'Thu', tasks: 10, hours: 7 },
  { name: 'Fri', tasks: 14, hours: 9 },
  { name: 'Sat', tasks: 4, hours: 3 },
  { name: 'Sun', tasks: 2, hours: 1.5 },
];

const monthlyData = [
  { name: 'Week 1', completed: 32, created: 28 },
  { name: 'Week 2', completed: 45, created: 38 },
  { name: 'Week 3', completed: 38, created: 42 },
  { name: 'Week 4', completed: 52, created: 48 },
];

const productivityData = [
  { name: 'Jan', value: 65 },
  { name: 'Feb', value: 72 },
  { name: 'Mar', value: 68 },
  { name: 'Apr', value: 80 },
  { name: 'May', value: 75 },
  { name: 'Jun', value: 85 },
  { name: 'Jul', value: 90 },
  { name: 'Aug', value: 82 },
  { name: 'Sep', value: 88 },
  { name: 'Oct', value: 92 },
];

const CustomTooltip = ({ active, payload, label }: any) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-3 shadow-xl">
        <p className="text-sm font-medium text-white mb-1">{label}</p>
        {payload.map((entry: any, index: number) => (
          <p key={index} className="text-xs" style={{ color: entry.color }}>
            {entry.name}: {entry.value}
          </p>
        ))}
      </div>
    );
  }
  return null;
};

export default function StatsPanel() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Analytics</h1>
        <p className="text-gray-400 mt-1">Track your productivity and progress</p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-gray-900 border border-gray-800 rounded-xl p-5"
        >
          <p className="text-sm text-gray-400">This Week</p>
          <p className="text-3xl font-bold mt-1">56 <span className="text-lg text-gray-500">tasks</span></p>
          <p className="text-sm text-emerald-400 mt-2">↑ 18% from last week</p>
        </motion.div>
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-gray-900 border border-gray-800 rounded-xl p-5"
        >
          <p className="text-sm text-gray-400">Avg. Daily Hours</p>
          <p className="text-3xl font-bold mt-1">5.8 <span className="text-lg text-gray-500">hrs</span></p>
          <p className="text-sm text-emerald-400 mt-2">↑ 12% from last week</p>
        </motion.div>
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-gray-900 border border-gray-800 rounded-xl p-5"
        >
          <p className="text-sm text-gray-400">Completion Rate</p>
          <p className="text-3xl font-bold mt-1">87<span className="text-lg text-gray-500">%</span></p>
          <p className="text-sm text-emerald-400 mt-2">↑ 5% from last month</p>
        </motion.div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-gray-900 border border-gray-800 rounded-xl p-5"
        >
          <h3 className="font-semibold mb-4">Weekly Activity</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={weeklyData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="name" stroke="#6B7280" fontSize={12} />
              <YAxis stroke="#6B7280" fontSize={12} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="tasks" fill="#8B5CF6" radius={[4, 4, 0, 0]} name="Tasks" />
            </BarChart>
          </ResponsiveContainer>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="bg-gray-900 border border-gray-800 rounded-xl p-5"
        >
          <h3 className="font-semibold mb-4">Monthly Progress</h3>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={monthlyData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="name" stroke="#6B7280" fontSize={12} />
              <YAxis stroke="#6B7280" fontSize={12} />
              <Tooltip content={<CustomTooltip />} />
              <Line type="monotone" dataKey="completed" stroke="#10B981" strokeWidth={2} dot={{ fill: '#10B981' }} name="Completed" />
              <Line type="monotone" dataKey="created" stroke="#6366F1" strokeWidth={2} dot={{ fill: '#6366F1' }} name="Created" />
            </LineChart>
          </ResponsiveContainer>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="bg-gray-900 border border-gray-800 rounded-xl p-5 lg:col-span-2"
        >
          <h3 className="font-semibold mb-4">Productivity Score</h3>
          <ResponsiveContainer width="100%" height={250}>
            <AreaChart data={productivityData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="name" stroke="#6B7280" fontSize={12} />
              <YAxis stroke="#6B7280" fontSize={12} />
              <Tooltip content={<CustomTooltip />} />
              <defs>
                <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#8B5CF6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#8B5CF6" stopOpacity={0} />
                </linearGradient>
              </defs>
              <Area type="monotone" dataKey="value" stroke="#8B5CF6" strokeWidth={2} fill="url(#colorScore)" name="Score" />
            </AreaChart>
          </ResponsiveContainer>
        </motion.div>
      </div>
    </div>
  );
}
