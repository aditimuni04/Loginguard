#pragma once
// Sliding-window helpers. Events must be fed in non-decreasing time order.
// Window semantics: an event at time t is "inside" the window ending at `now`
// when  now - windowSeconds <= t  (boundaries are INCLUSIVE).
// Every add/expire is amortised O(1): each element is pushed and popped once.

#include <cstdint>
#include <deque>
#include <limits>
#include <string>
#include <unordered_map>
#include <utility>

namespace lg {

// Plain list of timestamps (e.g. failed logins of one user from one IP).
class TimeWindow {
public:
    void push(int64_t ts) { q_.push_back(ts); }
    // Drops every timestamp strictly older than `cutoff` (cutoff = now - window).
    void expire(int64_t cutoff) {
        while (!q_.empty() && q_.front() < cutoff) q_.pop_front();
    }
    size_t size() const { return q_.size(); }
    bool empty() const { return q_.empty(); }
    int64_t newest() const { return q_.empty() ? std::numeric_limits<int64_t>::min() : q_.back(); }

private:
    std::deque<int64_t> q_;
};

// Window that also tracks how many DISTINCT values (usernames / IPs) it holds.
// A multiset-in-a-hashmap keeps distinct() O(1) while elements expire.
class SlidingDistinct {
public:
    void add(int64_t ts, const std::string& value) {
        q_.emplace_back(ts, value);
        ++counts_[value];
    }
    void expire(int64_t cutoff) {
        while (!q_.empty() && q_.front().first < cutoff) {
            auto it = counts_.find(q_.front().second);
            if (it != counts_.end() && --it->second == 0) counts_.erase(it);
            q_.pop_front();
        }
    }
    size_t total() const { return q_.size(); }
    size_t distinct() const { return counts_.size(); }
    bool empty() const { return q_.empty(); }
    int64_t newest() const {
        return q_.empty() ? std::numeric_limits<int64_t>::min() : q_.back().first;
    }

private:
    std::deque<std::pair<int64_t, std::string>> q_;
    std::unordered_map<std::string, int> counts_;
};

}  // namespace lg
