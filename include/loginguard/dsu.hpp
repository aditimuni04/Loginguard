#pragma once
// Disjoint-set union (Union-Find) with path compression + union by size.
// Amortised O(alpha(n)) per operation. Used to group alerts into "campaigns":
// alerts that share an IP or a username end up in the same set.

#include <cstddef>
#include <utility>
#include <vector>

namespace lg {

class DisjointSets {
public:
    // Adds a new singleton set and returns its id.
    int add() {
        int id = static_cast<int>(parent_.size());
        parent_.push_back(id);
        size_.push_back(1);
        return id;
    }

    // Iterative find with full path compression (no recursion => no stack risk).
    int find(int x) {
        int root = x;
        while (parent_[static_cast<size_t>(root)] != root) root = parent_[static_cast<size_t>(root)];
        while (parent_[static_cast<size_t>(x)] != root) {
            int next = parent_[static_cast<size_t>(x)];
            parent_[static_cast<size_t>(x)] = root;
            x = next;
        }
        return root;
    }

    // Returns true if a and b were in different sets (i.e. a merge happened).
    bool unite(int a, int b) {
        a = find(a);
        b = find(b);
        if (a == b) return false;
        if (size_[static_cast<size_t>(a)] < size_[static_cast<size_t>(b)]) std::swap(a, b);
        parent_[static_cast<size_t>(b)] = a;
        size_[static_cast<size_t>(a)] += size_[static_cast<size_t>(b)];
        return true;
    }

    bool connected(int a, int b) { return find(a) == find(b); }
    int setSize(int x) { return size_[static_cast<size_t>(find(x))]; }
    size_t elements() const { return parent_.size(); }

private:
    std::vector<int> parent_;
    std::vector<int> size_;
};

}  // namespace lg
