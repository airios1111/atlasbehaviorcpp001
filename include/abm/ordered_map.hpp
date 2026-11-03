// Insertion-ordered string-keyed map (the iteration semantics of a Python dict).
#pragma once

#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace abm {

template <class V>
class OrderedMap {
 public:
  using value_type = std::pair<std::string, V>;
  using iterator = typename std::vector<value_type>::iterator;
  using const_iterator = typename std::vector<value_type>::const_iterator;

  bool contains(const std::string& key) const { return index_.count(key) > 0; }
  std::size_t size() const { return items_.size(); }
  bool empty() const { return items_.empty(); }

  V* find(const std::string& key) {
    auto it = index_.find(key);
    return it == index_.end() ? nullptr : &items_[it->second].second;
  }
  const V* find(const std::string& key) const {
    auto it = index_.find(key);
    return it == index_.end() ? nullptr : &items_[it->second].second;
  }
  V& at(const std::string& key) {
    if (V* v = find(key)) return *v;
    throw std::out_of_range(key);
  }
  const V& at(const std::string& key) const {
    if (const V* v = find(key)) return *v;
    throw std::out_of_range(key);
  }

  // d[key] = value (keeps the original position when the key already exists)
  void set(const std::string& key, V value) {
    if (V* v = find(key)) {
      *v = std::move(value);
      return;
    }
    index_.emplace(key, items_.size());
    items_.emplace_back(key, std::move(value));
  }

  void erase(const std::string& key) {
    auto it = index_.find(key);
    if (it == index_.end()) return;
    items_.erase(items_.begin() + static_cast<std::ptrdiff_t>(it->second));
    index_.clear();
    for (std::size_t i = 0; i < items_.size(); ++i) index_.emplace(items_[i].first, i);
  }

  iterator begin() { return items_.begin(); }
  iterator end() { return items_.end(); }
  const_iterator begin() const { return items_.begin(); }
  const_iterator end() const { return items_.end(); }

 private:
  std::vector<value_type> items_;
  std::unordered_map<std::string, std::size_t> index_;
};

}  // namespace abm
