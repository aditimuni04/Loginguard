#pragma once
// Top-K selection with a bounded heap: O(n log k) time, O(k) extra memory.
// Much cheaper than sorting everything when k << n (e.g. "10 riskiest IPs").

#include <algorithm>
#include <cstdint>
#include <queue>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace lg {

// `better(a, b)` must be a strict weak ordering meaning "a ranks before b".
// For deterministic output it should break ties completely.
template <typename T, typename Better>
std::vector<T> topK(const std::vector<T>& items, size_t k, Better better) {
    std::vector<T> result;
    if (k == 0) return result;
    // priority_queue exposes its *largest* element under the comparator. With
    // comp == better, that is the WORST element kept so far - exactly the one
    // we want to evict first.
    std::priority_queue<T, std::vector<T>, Better> heap(better);
    for (const T& item : items) {
        if (heap.size() < k) {
            heap.push(item);
        } else if (better(item, heap.top())) {
            heap.pop();
            heap.push(item);
        }
    }
    result.reserve(heap.size());
    while (!heap.empty()) {
        result.push_back(heap.top());
        heap.pop();
    }
    std::reverse(result.begin(), result.end());  // worst-first -> best-first
    return result;
}

struct EntityRisk {
    std::string key;       // IP or username
    int64_t totalScore = 0;
    int maxScore = 0;
    int alerts = 0;
};

// Aggregates (entity, score) pairs and returns the k riskiest entities.
inline std::vector<EntityRisk> rankEntities(const std::vector<std::pair<std::string, int>>& scored, size_t k) {
    std::unordered_map<std::string, EntityRisk> agg;
    for (const auto& [key, score] : scored) {
        EntityRisk& r = agg[key];
        r.key = key;
        r.totalScore += score;
        r.maxScore = std::max(r.maxScore, score);
        ++r.alerts;
    }
    std::vector<EntityRisk> all;
    all.reserve(agg.size());
    for (auto& kv : agg) all.push_back(std::move(kv.second));
    return topK(all, k, [](const EntityRisk& a, const EntityRisk& b) {
        if (a.totalScore != b.totalScore) return a.totalScore > b.totalScore;
        if (a.maxScore != b.maxScore) return a.maxScore > b.maxScore;
        return a.key < b.key;
    });
}

}  // namespace lg
