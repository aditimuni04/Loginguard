#pragma once
// Binary trie over the 32 bits of an IPv4 address, for CIDR blacklist matching.
// Lookup is O(32) regardless of how many ranges are stored, and returns the
// LONGEST matching prefix (so a /32 entry wins over an overlapping /24).

#include <string>
#include <vector>

#include "loginguard/util.hpp"

namespace lg {

class CidrTrie {
public:
    CidrTrie() { nodes_.emplace_back(); }

    // Accepts "a.b.c.d/len" (0..32) or a bare "a.b.c.d" (== /32).
    // Returns false (and stores nothing) on invalid syntax.
    bool insert(const std::string& text) {
        std::string t = trim(text);
        std::string addr = t;
        int len = 32;
        size_t slash = t.find('/');
        if (slash != std::string::npos) {
            addr = t.substr(0, slash);
            std::string lenText = t.substr(slash + 1);
            if (lenText.empty() || lenText.size() > 2) return false;
            len = 0;
            for (char c : lenText) {
                if (c < '0' || c > '9') return false;
                len = len * 10 + (c - '0');
            }
            if (len > 32) return false;
        }
        uint32_t ip = 0;
        if (!parseIpv4(addr, ip)) return false;

        size_t node = 0;
        for (int i = 0; i < len; ++i) {
            int bit = static_cast<int>((ip >> (31 - i)) & 1u);
            if (nodes_[node].child[bit] < 0) {
                nodes_.emplace_back();  // may reallocate: never hold references across this
                nodes_[node].child[bit] = static_cast<int>(nodes_.size() - 1);
            }
            node = static_cast<size_t>(nodes_[node].child[bit]);
        }
        if (nodes_[node].entry < 0) {  // first definition of a prefix wins
            labels_.push_back(t);
            nodes_[node].entry = static_cast<int>(labels_.size() - 1);
        }
        return true;
    }

    // Index of the longest matching entry, or -1.
    int match(uint32_t ip) const {
        size_t node = 0;
        int best = nodes_[0].entry;
        for (int i = 0; i < 32; ++i) {
            int bit = static_cast<int>((ip >> (31 - i)) & 1u);
            int next = nodes_[node].child[bit];
            if (next < 0) break;
            node = static_cast<size_t>(next);
            if (nodes_[node].entry >= 0) best = nodes_[node].entry;
        }
        return best;
    }

    const std::string& label(int index) const { return labels_[static_cast<size_t>(index)]; }
    size_t size() const { return labels_.size(); }
    bool empty() const { return labels_.empty(); }

private:
    struct Node {
        int child[2] = {-1, -1};
        int entry = -1;
    };
    std::vector<Node> nodes_;
    std::vector<std::string> labels_;
};

}  // namespace lg
