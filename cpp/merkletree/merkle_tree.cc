#include "merkletree/merkle_tree.h"

#include <assert.h>
#include <stddef.h>
#include <string>
#include <vector>
#include <dpf_pir/hashdatastore.h>

#include "merkletree/merkle_tree_math.h"
#include "dpf_pir/dpf.h"

using cert_trans::MerkleTreeInterface;
using std::move;
using std::string;
using std::unique_ptr;

MerkleTree::MerkleTree(unique_ptr<SerialHasher> hasher)
    : MerkleTreeInterface(),
      treehasher_(move(hasher)),
      leaves_processed_(0),
      level_count_(0) {
}

MerkleTree::~MerkleTree() {
}

size_t MerkleTree::AddLeaf(const string& data) {
  return AddLeafHash(treehasher_.HashLeaf(data));
}

size_t MerkleTree::AddLeafHash(const string& hash) {
  if (LazyLevelCount() == 0) {
    AddLevel();
    // The first leaf hash is also the first root.
    leaves_processed_ = 1;
  }
  PushBack(0, hash);
  size_t leaf_count = LeafCount();
  // Update level count: a k-level tree can hold 2^{k-1} leaves,
  // so increment level count every time we overflow a power of two.
  // Do not update the root; we evaluate the tree lazily.
  if (MerkleTreeMath::IsPowerOfTwoPlusOne(leaf_count))
    ++level_count_;
  // Return the current leaf count.
  return leaf_count;
}

string MerkleTree::CurrentRoot() {
  return RootAtSnapshot(LeafCount());
}

string MerkleTree::RootAtSnapshot(size_t snapshot) {
  if (snapshot == 0)
    return treehasher_.HashEmpty();
  size_t leaf_count = LeafCount();
  if (snapshot > leaf_count)
    return string();
  if (snapshot >= leaves_processed_)
    return UpdateToSnapshot(snapshot);
  // snapshot < leaves_processed_: recompute the snapshot root.
  return RecomputePastSnapshot(snapshot, 0, NULL);
}

std::vector<string> MerkleTree::PathToCurrentRoot(size_t leaf) {
  return PathToRootAtSnapshot(leaf, LeafCount());
}

std::vector<string> MerkleTree::PathToRootAtSnapshot(size_t leaf,
                                                     size_t snapshot) {
  std::vector<string> path;
  size_t leaf_count = LeafCount();
  if (leaf > snapshot || snapshot > leaf_count || leaf == 0)
    return path;
  return PathFromNodeToRootAtSnapshot(leaf - 1, 0, snapshot);
}

std::vector<string> MerkleTree::SnapshotConsistency(size_t snapshot1,
                                                    size_t snapshot2) {
  std::vector<string> proof;
  size_t leaf_count = LeafCount();
  if (snapshot1 == 0 || snapshot1 >= snapshot2 || snapshot2 > leaf_count)
    return proof;

  size_t level = 0;
  // Rightmost node in snapshot1.
  size_t node = snapshot1 - 1;
  // Compute the (compressed) path to the root of snapshot2.
  // Everything left of 'node' is equal in both trees; no need to record.
  while (MerkleTreeMath::IsRightChild(node)) {
    node = MerkleTreeMath::Parent(node);
    ++level;
  }

  if (snapshot2 > leaves_processed_) {
    // Bring the tree sufficiently up to date.
    UpdateToSnapshot(snapshot2);
  }

  // Record the node, unless we already reached the root of snapshot1.
  if (node)
    proof.push_back(Node(level, node));

  // Now record the path from this node to the root of snapshot2.
  std::vector<string> path =
      PathFromNodeToRootAtSnapshot(node, level, snapshot2);
  proof.insert(proof.end(), path.begin(), path.end());
  return proof;
}

string MerkleTree::UpdateToSnapshot(size_t snapshot) {
  if (snapshot == 0)
    return treehasher_.HashEmpty();
  if (snapshot == 1)
    return Node(0, 0);
  if (snapshot == leaves_processed_)
    return Root();
  assert(snapshot <= LeafCount());
  assert(snapshot > leaves_processed_);

  // Update tree, moving up level-by-level.
  size_t level = 0;
  // Index of the first node to be processed at the current level.
  size_t first_node = leaves_processed_;
  // Index of the last node.
  size_t last_node = snapshot - 1;

  // Process level-by-level until we converge to a single node.
  // (first_node, last_node) = (0, 0) means we have reached the root level.
  while (last_node) {
    if (LazyLevelCount() <= level + 1) {
      AddLevel();
    } else if (NodeCount(level + 1) ==
               MerkleTreeMath::Parent(first_node) + 1) {
      // The leftmost parent at level 'level+1' may already exist,
      // so we need to update it. Nuke the old parent.
      PopBack(level + 1);
    }

    // Compute the parents of new nodes at the current level.
    // Start with a left sibling and parse an even number of nodes.
    for (size_t j = first_node & ~1; j < last_node; j += 2) {
      PushBack(level + 1,
               treehasher_.HashChildren(Node(level, j), Node(level, j + 1)));
    }
    // If the last node at the current level is a left sibling,
    // dummy-propagate it one level up.
    if (!MerkleTreeMath::IsRightChild(last_node))
      PushBack(level + 1, Node(level, last_node));

    first_node = MerkleTreeMath::Parent(first_node);
    last_node = MerkleTreeMath::Parent(last_node);
    ++level;
  };

  leaves_processed_ = snapshot;
  return Root();
}

string MerkleTree::RecomputePastSnapshot(size_t snapshot, size_t node_level,
                                         string* node) {
  size_t level = 0;
  // Index of the rightmost node at the current level for this snapshot.
  size_t last_node = snapshot - 1;

  if (snapshot == leaves_processed_) {
    // Nothing to recompute.
    if (node && LazyLevelCount() > node_level) {
      if (node_level > 0) {
        node->assign(LastNode(node_level));
      } else {
        // Leaf level: grab the last processed leaf.
        node->assign(Node(node_level, last_node));
      }
    }
    return Root();
  }

  assert(snapshot < leaves_processed_);

  // Recompute nodes on the path of the last leaf.
  while (MerkleTreeMath::IsRightChild(last_node)) {
    if (node && node_level == level)
      node->assign(Node(level, last_node));
    // Left sibling and parent exist in the snapshot, and are equal to
    // those in the tree; no need to rehash, move one level up.
    last_node = MerkleTreeMath::Parent(last_node);
    ++level;
  }

  // Now last_node is the index of a left sibling with no right sibling.
  // Record the node.
  string subtree_root = Node(level, last_node);

  if (node && node_level == level)
    node->assign(subtree_root);

  while (last_node) {
    if (MerkleTreeMath::IsRightChild(last_node)) {
      // Recompute the parent of tree_[level][last_node].
      subtree_root =
          treehasher_.HashChildren(Node(level, last_node - 1), subtree_root);
    }
    // Else the parent is a dummy copy of the current node; do nothing.

    last_node = MerkleTreeMath::Parent(last_node);
    ++level;
    if (node && node_level == level)
      node->assign(subtree_root);
  }

  return subtree_root;
}

std::vector<string> MerkleTree::PathFromNodeToRootAtSnapshot(size_t node,
                                                             size_t level,
                                                             size_t snapshot) {
  std::vector<string> path;
  if (snapshot == 0)
    return path;
  // Index of the last node.
  size_t last_node = (snapshot - 1) >> level;
  if (level >= level_count_ || node > last_node || snapshot > LeafCount())
    return path;

  if (snapshot > leaves_processed_) {
    // Bring the tree sufficiently up to date.
    UpdateToSnapshot(snapshot);
  }

  // Move up, recording the sibling of the current node at each level.
  while (last_node) {
    size_t sibling = MerkleTreeMath::Sibling(node);
    if (sibling < last_node) {
      // The sibling is not the last node of the level in the snapshot
      // tree, so its value is correct in the tree.
      path.push_back(Node(level, sibling));
    } else if (sibling == last_node) {
      // The sibling is the last node of the level in the snapshot tree,
      // so we get its value for the snapshot. Get the root in the same pass.
      string recompute_node;
      RecomputePastSnapshot(snapshot, level, &recompute_node);
      path.push_back(recompute_node);
    }
    // Else sibling > last_node so the sibling does not exist. Do nothing.
    // Continue moving up in the tree, ignoring dummy copies.

    node = MerkleTreeMath::Parent(node);
    last_node = MerkleTreeMath::Parent(last_node);
    ++level;
  };

  return path;
}

std::string MerkleTree::Node(size_t level, size_t index) const {
  assert(NodeCount(level) > index);
  String ref = tree_[level].substr(index * treehasher_.DigestSize(), treehasher_.DigestSize());
  return std::string(ref.begin(), ref.end());
}

string MerkleTree::NodeDPF(size_t level, const std::vector<uint8_t>& DPF_key) {
  //set hashdatastore to leveldb.data()
  //evaluate DPF & answer query
  std::vector<uint8_t> DPF_keystream = DPF::EvalFull8(DPF_key, tree_.size() - level);
  MerkleTree::String& leveldata = tree_[level];
  span<hashdatastore::hash_type> leveldb(reinterpret_cast<hashdatastore::hash_type*>(&leveldata[0]), leveldata.size() / sizeof(hashdatastore::hash_type));
  hashdatastore store(leveldb);
  hashdatastore::hash_type answer = store.answer_pir2(DPF_keystream);
  return std::string((reinterpret_cast<char*>(&answer)), reinterpret_cast<char*>(&answer) + sizeof(hashdatastore::hash_type));
}

string MerkleTree::Root() const {
  assert(tree_.back().size() == treehasher_.DigestSize());
  return std::string(tree_.back().begin(), tree_.back().end());
}

size_t MerkleTree::NodeCount(size_t level) const {
  assert(LazyLevelCount() > level);
  return tree_[level].size() / treehasher_.DigestSize();
}

string MerkleTree::LastNode(size_t level) const {
  assert(NodeCount(level) >= 1U);
  MerkleTree::String tmp = tree_[level].substr(tree_[level].size() - treehasher_.DigestSize());
  return std::string(tmp.begin(), tmp.end());
}

void MerkleTree::PopBack(size_t level) {
  assert(NodeCount(level) >= 1U);
  tree_[level].erase(tree_[level].size() - treehasher_.DigestSize());
}

void MerkleTree::PushBack(size_t level, string node) {
  assert(node.size() == treehasher_.DigestSize());
  assert(LazyLevelCount() > level);
  tree_[level].append(node.begin(), node.end());
}

void MerkleTree::AddLevel() {
  tree_.push_back(MerkleTree::String());
}

size_t MerkleTree::LazyLevelCount() const {
  return tree_.size();
}

MutableMerkleTree::MutableMerkleTree(unique_ptr<SerialHasher> hasher)
    : MerkleTree(move(hasher)) {
}

MutableMerkleTree::~MutableMerkleTree() {
}

bool MutableMerkleTree::UpdateLeafHash(size_t leaf, const string& hash) {
  if (leaf == 0 || leaf > LeafCount())
    return false;

  // Update the leaf node.
  size_t child = leaf - 1;
  tree_[0].replace(treehasher_.DigestSize() * child, treehasher_.DigestSize(),
                   MerkleTree::String(hash.begin(), hash.end()));

  if (leaf > leaves_processed_)
    return true;

  // Update the parents chain, level by level.
  size_t child_level = 0;
  size_t parent = MerkleTreeMath::Parent(child);
  string parent_hash;
  while (child) {
    if (MerkleTreeMath::IsRightChild(child)) {
      parent_hash = treehasher_.HashChildren(Node(child_level, child - 1),
                                             Node(child_level, child));
    } else if (child < NodeCount(child_level) - 1) {
      parent_hash = treehasher_.HashChildren(Node(child_level, child),
                                             Node(child_level, child + 1));
    } else {
      // Propagate the "dummy" node.
      parent_hash = Node(child_level, child);
    }

    tree_[child_level + 1].replace(treehasher_.DigestSize() * parent,
                                   treehasher_.DigestSize(), MerkleTree::String(parent_hash.begin(), parent_hash.end()));

    child = parent;
    parent = MerkleTreeMath::Parent(parent);
    ++child_level;
  }

  return true;
}

bool MutableMerkleTree::Truncate(size_t leaf) {
  if (leaf > LeafCount())
    return false;

  if (leaf == 0) {
    tree_.clear();
    leaves_processed_ = 0;
    level_count_ = 0;

    return true;
  }

  // Truncate leaves level.
  size_t child = leaf - 1;
  tree_[0].erase(treehasher_.DigestSize() * (child + 1));

  // Update levels count.
  level_count_ = 1;
  while (child) {
    ++level_count_;
    child = MerkleTreeMath::Parent(child);
  }

  if (leaf > leaves_processed_)
    return true;

  // Truncate each level above the leaves level.
  child = leaf - 1;
  size_t child_level = 0;
  size_t parent = MerkleTreeMath::Parent(child);
  while (child) {
    tree_[child_level + 1].erase(treehasher_.DigestSize() * (parent + 1));

    child = parent;
    parent = MerkleTreeMath::Parent(parent);
    ++child_level;
  }

  // The current child_level value corresponds to the root level - remove empty
  // levels.
  if (child_level + 1 < tree_.size())
    tree_.erase(tree_.begin() + child_level + 1, tree_.end());

  // Update rightmost chain of nodes.
  assert(UpdateLeafHash(leaf, LeafHash(leaf)));

  return true;
}
