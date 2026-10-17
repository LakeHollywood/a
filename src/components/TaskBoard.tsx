import { useState } from 'react';
import { motion } from 'framer-motion';
import { Plus, GripVertical, Calendar, Flag, MoreHorizontal } from 'lucide-react';

interface Task {
  id: string;
  title: string;
  priority: 'low' | 'medium' | 'high';
  dueDate: string;
  tags: string[];
}

interface Column {
  id: string;
  title: string;
  color: string;
  tasks: Task[];
}

const initialColumns: Column[] = [
  {
    id: 'todo',
    title: 'To Do',
    color: 'bg-gray-500',
    tasks: [
      { id: '1', title: 'Design new landing page', priority: 'high', dueDate: 'Oct 20', tags: ['Design'] },
      { id: '2', title: 'Write API documentation', priority: 'medium', dueDate: 'Oct 22', tags: ['Docs'] },
      { id: '3', title: 'Set up CI/CD pipeline', priority: 'low', dueDate: 'Oct 25', tags: ['DevOps'] },
    ],
  },
  {
    id: 'in-progress',
    title: 'In Progress',
    color: 'bg-blue-500',
    tasks: [
      { id: '4', title: 'Implement auth flow', priority: 'high', dueDate: 'Oct 18', tags: ['Backend'] },
      { id: '5', title: 'Create dashboard charts', priority: 'medium', dueDate: 'Oct 19', tags: ['Frontend'] },
    ],
  },
  {
    id: 'review',
    title: 'In Review',
    color: 'bg-amber-500',
    tasks: [
      { id: '6', title: 'User onboarding flow', priority: 'high', dueDate: 'Oct 17', tags: ['UX'] },
    ],
  },
  {
    id: 'done',
    title: 'Done',
    color: 'bg-emerald-500',
    tasks: [
      { id: '7', title: 'Database schema design', priority: 'medium', dueDate: 'Oct 15', tags: ['Backend'] },
      { id: '8', title: 'Setup project repo', priority: 'low', dueDate: 'Oct 12', tags: ['DevOps'] },
    ],
  },
];

const priorityColors = {
  low: 'text-gray-400 bg-gray-400/10',
  medium: 'text-amber-400 bg-amber-400/10',
  high: 'text-red-400 bg-red-400/10',
};

const tagColors: Record<string, string> = {
  Design: 'bg-pink-500/10 text-pink-400',
  Docs: 'bg-blue-500/10 text-blue-400',
  DevOps: 'bg-orange-500/10 text-orange-400',
  Backend: 'bg-green-500/10 text-green-400',
  Frontend: 'bg-violet-500/10 text-violet-400',
  UX: 'bg-cyan-500/10 text-cyan-400',
};

export default function TaskBoard() {
  const [columns, setColumns] = useState<Column[]>(initialColumns);
  const [draggedTask, setDraggedTask] = useState<{ taskId: string; fromColumn: string } | null>(null);

  const handleDragStart = (taskId: string, fromColumn: string) => {
    setDraggedTask({ taskId, fromColumn });
  };

  const handleDrop = (toColumn: string) => {
    if (!draggedTask) return;
    
    setColumns(prev => {
      const newColumns = prev.map(col => ({ ...col, tasks: [...col.tasks] }));
      const fromCol = newColumns.find(c => c.id === draggedTask.fromColumn);
      const toCol = newColumns.find(c => c.id === toColumn);
      
      if (!fromCol || !toCol) return prev;
      
      const taskIndex = fromCol.tasks.findIndex(t => t.id === draggedTask.taskId);
      if (taskIndex === -1) return prev;
      
      const [task] = fromCol.tasks.splice(taskIndex, 1);
      toCol.tasks.push(task);
      
      return newColumns;
    });
    
    setDraggedTask(null);
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">Task Board</h1>
          <p className="text-gray-400 mt-1">Drag and drop tasks between columns</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-violet-600 hover:bg-violet-700 rounded-lg text-sm font-medium transition-colors">
          <Plus className="w-4 h-4" />
          Add Task
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        {columns.map((column) => (
          <div
            key={column.id}
            className="bg-gray-900 border border-gray-800 rounded-xl p-4"
            onDragOver={(e) => e.preventDefault()}
            onDrop={() => handleDrop(column.id)}
          >
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <div className={`w-2.5 h-2.5 rounded-full ${column.color}`}></div>
                <h3 className="font-semibold text-sm">{column.title}</h3>
                <span className="text-xs text-gray-500 bg-gray-800 px-2 py-0.5 rounded-full">
                  {column.tasks.length}
                </span>
              </div>
              <button className="p-1 rounded hover:bg-gray-800 transition-colors">
                <MoreHorizontal className="w-4 h-4 text-gray-500" />
              </button>
            </div>

            <div className="space-y-3 min-h-[100px]">
              {column.tasks.map((task) => (
                <motion.div
                  key={task.id}
                  layout
                  draggable
                  onDragStart={() => handleDragStart(task.id, column.id)}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  className="bg-gray-800 border border-gray-700 rounded-lg p-3 cursor-grab active:cursor-grabbing hover:border-gray-600 transition-colors"
                >
                  <div className="flex items-start gap-2">
                    <GripVertical className="w-4 h-4 text-gray-600 mt-0.5 flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-white truncate">{task.title}</p>
                      <div className="flex items-center gap-2 mt-2">
                        <span className={`text-xs px-2 py-0.5 rounded-full ${priorityColors[task.priority]}`}>
                          {task.priority}
                        </span>
                        <span className="text-xs text-gray-500 flex items-center gap-1">
                          <Calendar className="w-3 h-3" />
                          {task.dueDate}
                        </span>
                      </div>
                      <div className="flex gap-1.5 mt-2">
                        {task.tags.map(tag => (
                          <span key={tag} className={`text-xs px-2 py-0.5 rounded-full ${tagColors[tag] || 'bg-gray-700 text-gray-300'}`}>
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
