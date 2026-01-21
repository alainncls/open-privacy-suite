import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { rbacApi } from '@/api/rbac';
import type { User } from '@/types/rbac';
import UserDetail from './UserDetail';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Users,
  User as UserIcon,
  Shield,
  ShieldOff,
  Check,
  X,
  Loader2,
  Eye,
} from 'lucide-react';

export default function UserList() {
  const { userId } = useParams();
  const navigate = useNavigate();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);

  useEffect(() => {
    loadUsers();
  }, []);

  // Open modal if userId is in URL
  useEffect(() => {
    if (userId && users.length > 0) {
      const user = users.find(u => u.id === userId);
      if (user) {
        setSelectedUser(user);
      }
    } else if (!userId) {
      setSelectedUser(null);
    }
  }, [userId, users]);

  const loadUsers = async () => {
    try {
      setLoading(true);
      const response = await rbacApi.users.list();
      setUsers(response.data || []);
    } catch (error) {
      console.error('Failed to load users:', error);
      setUsers([]);
    } finally {
      setLoading(false);
    }
  };

  const handleToggleBan = async (user: User) => {
    try {
      await rbacApi.users.update(user.id, { banned: !user.banned });
      await loadUsers();
    } catch (error) {
      console.error('Failed to update user:', error);
      alert('Failed to update user.');
    }
  };

  const handleUserUpdate = async () => {
    await loadUsers();
    // Update selected user with fresh data
    if (selectedUser) {
      const updated = users.find(u => u.id === selectedUser.id);
      if (updated) setSelectedUser(updated);
    }
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  };

  const truncateId = (id: string) => {
    if (id.length <= 20) return id;
    return `${id.slice(0, 10)}...${id.slice(-8)}`;
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-medium text-white/80">Users</h3>
          <p className="text-xs text-white/50 mt-0.5">
            Manage user accounts, KYC status, and group memberships
          </p>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 text-white/40 animate-spin" />
        </div>
      ) : users.length === 0 ? (
        <div className="text-center py-12">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-white/5 flex items-center justify-center">
            <Users className="w-8 h-8 text-white/30" />
          </div>
          <p className="text-white/50 mb-2">No users found</p>
          <p className="text-white/40 text-sm">
            Users are created automatically when they authenticate
          </p>
        </div>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>External ID</TableHead>
              <TableHead>KYC</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Created</TableHead>
              <TableHead>Note</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {users.map((user, index) => (
              <TableRow
                key={user.id}
                className="animate-fade-in cursor-pointer hover:bg-white/5"
                style={{ animationDelay: `${index * 30}ms` }}
                onClick={() => navigate(`/admin/rbac/users/${user.id}`)}
              >
                <TableCell>
                  <div className="flex items-center gap-2">
                    <UserIcon className="w-4 h-4 text-primary-400" />
                    <span
                      className="font-mono text-sm"
                      title={user.external_id}
                    >
                      {truncateId(user.external_id)}
                    </span>
                  </div>
                </TableCell>
                <TableCell>
                  {user.kyc ? (
                    <div className="flex items-center gap-1.5 text-green-400">
                      <Check className="w-4 h-4" />
                      <span className="text-sm">Verified</span>
                    </div>
                  ) : (
                    <div className="flex items-center gap-1.5 text-white/40">
                      <X className="w-4 h-4" />
                      <span className="text-sm">No</span>
                    </div>
                  )}
                </TableCell>
                <TableCell>
                  {user.banned ? (
                    <Badge variant="destructive" className="gap-1">
                      <ShieldOff className="w-3 h-3" />
                      Banned
                    </Badge>
                  ) : (
                    <Badge variant="success" className="gap-1">
                      <Shield className="w-3 h-3" />
                      Active
                    </Badge>
                  )}
                </TableCell>
                <TableCell className="text-white/60 text-sm">
                  {formatDate(user.created_at)}
                </TableCell>
                <TableCell className="text-white/60 text-sm max-w-[150px] truncate">
                  {user.note || '-'}
                </TableCell>
                <TableCell>
                  <div
                    className="flex items-center justify-end gap-2"
                    onClick={e => e.stopPropagation()}
                  >
                    <Button
                      variant={user.banned ? 'success' : 'destructive'}
                      size="sm"
                      onClick={() => handleToggleBan(user)}
                      className="gap-1.5"
                      title={user.banned ? 'Unban this user' : 'Ban this user'}
                    >
                      {user.banned ? (
                        <>
                          <Shield className="w-3.5 h-3.5" />
                          Unban
                        </>
                      ) : (
                        <>
                          <ShieldOff className="w-3.5 h-3.5" />
                          Ban
                        </>
                      )}
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => navigate(`/admin/rbac/users/${user.id}`)}
                      title="View user details"
                    >
                      <Eye className="w-4 h-4" />
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      {/* User Detail Dialog */}
      <Dialog
        open={!!selectedUser}
        onOpenChange={open => !open && navigate('/admin/rbac/users')}
      >
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <UserIcon className="w-5 h-5 text-primary-400" />
              User Details
            </DialogTitle>
          </DialogHeader>
          {selectedUser && (
            <UserDetail
              user={selectedUser}
              onUpdate={handleUserUpdate}
            />
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
