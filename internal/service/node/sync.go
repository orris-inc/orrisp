package node

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/easayliu/orrisp/internal/api"
)

// syncUsers synchronizes user list from the API
func (s *Service) syncUsers() error {
	s.logger.Debug("Synchronizing user list...")

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	users, err := s.apiClient.GetSubscriptions(ctx)
	if err != nil {
		return fmt.Errorf("failed to get user list: %w", err)
	}

	s.mu.Lock()
	oldUsers := s.currentUsers
	s.currentUsers = users
	s.mu.Unlock()

	// Update traffic tracker user mapping
	s.updateUserMap(users)

	s.logger.Info("User list synchronized successfully",
		slog.Int("old_count", len(oldUsers)),
		slog.Int("new_count", len(users)),
	)

	// Check if user list actually changed (compare content, not just count)
	changed := s.usersChanged(oldUsers, users)

	// Check singboxService under read lock to avoid race condition
	s.mu.RLock()
	hasSingbox := s.singboxService != nil
	s.mu.RUnlock()

	if changed && hasSingbox {
		s.logger.Info("User list changed, reloading sing-box...",
			slog.Int("old_users", len(oldUsers)),
			slog.Int("new_users", len(users)),
		)
		if err := s.reloadSingbox(); err != nil {
			s.logger.Error("Failed to reload sing-box", slog.Any("err", err))
			return err
		}
		s.logger.Info("sing-box reloaded with new user list")
	} else {
		s.logger.Info("User list sync completed",
			slog.Bool("changed", changed),
			slog.Bool("singbox_running", hasSingbox),
		)
	}

	return nil
}

// usersChanged checks if the user list has actually changed
// Returns true if users are different, false if they are the same
func (s *Service) usersChanged(oldUsers, newUsers []api.Subscription) bool {
	// Different lengths means definitely changed
	if len(oldUsers) != len(newUsers) {
		s.logger.Debug("User count changed",
			slog.Int("old", len(oldUsers)),
			slog.Int("new", len(newUsers)),
		)
		return true
	}

	// Build map of old users for efficient lookup
	oldMap := make(map[string]api.Subscription, len(oldUsers))
	for _, user := range oldUsers {
		oldMap[user.Name] = user
	}

	// Check if any new user is different or missing
	for _, newUser := range newUsers {
		oldUser, exists := oldMap[newUser.Name]
		if !exists {
			// New user added
			s.logger.Debug("New user detected", slog.String("name", newUser.Name))
			return true
		}
		// Check if user details changed
		if oldUser.SubscriptionSID != newUser.SubscriptionSID ||
			oldUser.Password != newUser.Password {
			s.logger.Debug("User details changed", slog.String("name", newUser.Name))
			return true
		}
	}

	// All users are the same
	return false
}

// updateUserMap updates the traffic tracker's user mapping
func (s *Service) updateUserMap(users []api.Subscription) {
	userMap := make(map[string]string, len(users))
	for _, user := range users {
		userMap[user.Name] = user.SubscriptionSID
	}
	s.trafficTracker.SetUserMap(userMap)
}

// applySubscriptionChanges applies subscription changes and returns old count, new count, and whether changes were made.
func (s *Service) applySubscriptionChanges(sync *api.SubscriptionSyncData) (oldCount, newCount int, changed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	oldCount = len(s.currentUsers)

	switch sync.ChangeType {
	case api.SubscriptionChangeAdded:
		changed = s.addSubscriptions(sync.Subscriptions)

	case api.SubscriptionChangeUpdated:
		changed = s.updateSubscriptions(sync.Subscriptions)

	case api.SubscriptionChangeRemoved:
		changed = s.removeSubscriptions(sync.Subscriptions)

	default:
		s.logger.Warn("Unknown subscription change type", slog.String("type", sync.ChangeType))
		return oldCount, oldCount, false
	}

	newCount = len(s.currentUsers)

	if changed {
		s.updateUserMap(s.currentUsers)
	}

	return oldCount, newCount, changed
}

// addSubscriptions adds new subscriptions if they don't already exist.
func (s *Service) addSubscriptions(subs []api.Subscription) bool {
	changed := false
	for _, sub := range subs {
		exists := false
		for _, existing := range s.currentUsers {
			if existing.SubscriptionSID == sub.SubscriptionSID {
				exists = true
				break
			}
		}
		if !exists {
			s.currentUsers = append(s.currentUsers, sub)
			changed = true
			s.logger.Debug("Subscription added", slog.String("name", sub.Name))
		}
	}
	return changed
}

// updateSubscriptions updates existing subscriptions.
func (s *Service) updateSubscriptions(subs []api.Subscription) bool {
	changed := false
	for _, sub := range subs {
		for i, existing := range s.currentUsers {
			if existing.SubscriptionSID == sub.SubscriptionSID {
				s.currentUsers[i] = sub
				changed = true
				s.logger.Debug("Subscription updated", slog.String("name", sub.Name))
				break
			}
		}
	}
	return changed
}

// removeSubscriptions removes subscriptions by their IDs.
func (s *Service) removeSubscriptions(subs []api.Subscription) bool {
	if len(subs) == 0 {
		return false
	}

	removedIDs := make(map[string]bool, len(subs))
	for _, sub := range subs {
		removedIDs[sub.SubscriptionSID] = true
	}

	changed := false
	newUsers := make([]api.Subscription, 0, len(s.currentUsers))
	for _, existing := range s.currentUsers {
		if !removedIDs[existing.SubscriptionSID] {
			newUsers = append(newUsers, existing)
		} else {
			s.logger.Debug("Subscription removed", slog.String("name", existing.Name))
			changed = true
		}
	}
	s.currentUsers = newUsers
	return changed
}
