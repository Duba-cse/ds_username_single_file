#include <iostream>
#include <unordered_map>
#include <vector>
#include <bitset>
#include <string>
#include <fstream>
#include <algorithm>
#include <functional>
#include <chrono>
#include <iomanip>
#include <cmath>

using namespace std;
using namespace chrono;

// Small helper to measure average time (ns) of an action over multiple repetitions
template<typename Func>
double measure_avg_ns(Func f, int repetitions, size_t ops_count){
    using clock = high_resolution_clock;
    if(repetitions <= 0) repetitions = 1;
    auto start = clock::now();
    for(int i = 0; i < repetitions; ++i) f();
    auto end = clock::now();
    double total_ns = static_cast<double>(duration_cast<nanoseconds>(end - start).count());
    size_t denom = (ops_count == 0) ? 1 : ops_count;
    return total_ns / (static_cast<double>(repetitions) * static_cast<double>(denom));
}

// ---------------------------- Utility Functions ----------------------------
vector<string> read_usernames(const string &filename) {
    vector<string> names;
    ifstream infile(filename);
    string line;
    while (getline(infile, line))
        if (!line.empty()) names.push_back(line);
    return names;
}

void write_results(const string &filename, const vector<string> &usernames,
                   const vector<vector<bool>> &status, const vector<string> &structure_names) {
    ofstream outfile(filename);
    for (size_t i = 0; i < usernames.size(); i++) {
        outfile << usernames[i] << " : ";
        for (size_t j = 0; j < structure_names.size(); j++)
            outfile << structure_names[j] << "=" << (status[j][i] ? "Taken" : "Available") << " ";
        outfile << "\n";
    }
}

// ---------------------------- Data Structures ----------------------------
class HashMapChecker {
    unordered_map<string,bool> store;
public:
    void insert(const string &u){ store[u]=true; }
    bool search(const string &u){ return store.count(u); }
    void remove(const string &u){ store.erase(u); }
    size_t memory_usage() const { 
        // Approx: 32 bytes overhead per entry + avg 10 bytes per string
        return store.size() * (32 + 10);
    }
};

// Bloom Filter with moderate size for 1-2% FP rate demonstration
// Reduced from optimal size to show controlled false positives
class BloomFilterChecker {
    static const int BITS = 500000;   // 500K bits (~62.5 KB) for ~1-2% FP rate
    static const int HASH_COUNT = 6;   // 6 hash functions
    vector<bool> bits;
    
    vector<size_t> hashes(const string &s){
        vector<size_t> h;
        hash<string> hasher;
        size_t hash1 = hasher(s);
        size_t hash2 = hasher(s + "salt");
        
        // Double hashing: h(i) = hash1 + i*hash2
        for(int i = 0; i < HASH_COUNT; i++){
            h.push_back((hash1 + i * hash2) % BITS);
        }
        return h;
    }
public:
    BloomFilterChecker() : bits(BITS, false) {}
    void insert(const string &u){ for(auto h : hashes(u)) bits[h] = true; }
    bool search(const string &u){ 
        for(auto h : hashes(u)) 
            if(!bits[h]) return false; 
        return true; 
    }
    size_t memory_usage() const { 
        // vector<bool> uses 1 bit per element
        return BITS / 8;  // Convert bits to bytes
    }
};

// Counting Bloom Filter with moderate size for 0.5-1.5% FP rate
class CountingBloomChecker {
    static const int SIZE = 600000;     // 600K counters (~586 KB) for ~0.5-1.5% FP rate
    static const int HASH_COUNT = 6;     // 6 hash functions
    vector<uint8_t> counters;  // 8-bit counters to save space
    
    vector<size_t> hashes(const string &s){
        vector<size_t> h;
        hash<string> hasher;
        size_t hash1 = hasher(s);
        size_t hash2 = hasher(s + "salt");
        
        for(int i = 0; i < HASH_COUNT; i++){
            h.push_back((hash1 + i * hash2) % SIZE);
        }
        return h;
    }
public:
    CountingBloomChecker() : counters(SIZE, 0) {}
    void insert(const string &u){ 
        for(auto h : hashes(u)) 
            if(counters[h] < 255) counters[h]++; 
    }
    bool search(const string &u){ 
        for(auto h : hashes(u)) 
            if(counters[h] == 0) return false; 
        return true; 
    }
    void remove(const string &u){ 
        for(auto h : hashes(u)) 
            if(counters[h] > 0) counters[h]--; 
    }
    size_t memory_usage() const { 
        // uint8_t = 1 byte per counter
        return SIZE * sizeof(uint8_t);
    }
};

struct TrieNode{ bool is_end=false; unordered_map<char,TrieNode*> children; };
class TrieChecker {
    TrieNode* root;
    size_t node_count;
public:
    TrieChecker(){ root=new TrieNode(); node_count=1; }
    void insert(const string &u){
        TrieNode* node=root;
        for(char c:u){
            if(!node->children.count(c)) {
                node->children[c]=new TrieNode();
                node_count++;
            }
            node=node->children[c];
        }
        node->is_end=true;
    }
    bool search(const string &u){
        TrieNode* node=root;
        for(char c:u){
            if(!node->children.count(c)) return false;
            node=node->children[c];
        }
        return node->is_end;
    }
    size_t memory_usage() const { 
        // Approx: 48 bytes per node (bool + map overhead)
        return node_count * 48;
    }
};

// Cuckoo Filter with fingerprints for controlled false positive demonstration
class CuckooFilterChecker{
    static const int BUCKETS = 150000;  // 150K buckets for extremely low load factor
    static const int ENTRIES_PER_BUCKET = 4;
    static const int FINGERPRINT_SIZE = 8;  // Small 8-bit fingerprints for collisions
    vector<vector<uint8_t>> table;  // Store fingerprints instead of full strings
    
    uint8_t get_fingerprint(const string &s){
        hash<string> hasher;
        size_t hash_val = hasher(s);
        // Ensure fingerprint is never 0 (reserved for empty slots)
        uint8_t fp = (hash_val & 0xFF);
        return (fp == 0) ? 1 : fp;
    }
    
    size_t hash1(const string &s){ 
        return hash<string>{}(s) % BUCKETS; 
    }
    size_t hash2(uint8_t fingerprint, size_t h1){ 
        return (h1 ^ (hash<uint8_t>{}(fingerprint))) % BUCKETS; 
    }
    
public:
    CuckooFilterChecker(){ 
        table.resize(BUCKETS);
        for(auto &bucket : table) bucket.reserve(ENTRIES_PER_BUCKET);
    }
    
    void insert(const string &u){
        uint8_t fingerprint = get_fingerprint(u);
        size_t h1 = hash1(u);
        size_t h2 = hash2(fingerprint, h1);
        
        // Try first bucket
        if(table[h1].size() < ENTRIES_PER_BUCKET){
            table[h1].push_back(fingerprint);
            return;
        }
        
        // Try second bucket
        if(table[h2].size() < ENTRIES_PER_BUCKET){
            table[h2].push_back(fingerprint);
            return;
        }
        
        // Both buckets full - simple approach: just add to first bucket
        // This will cause some overwrites but ensures we don't lose too many items
        table[h1].push_back(fingerprint);
    }
    
    bool search(const string &u){ 
        uint8_t fingerprint = get_fingerprint(u);
        size_t h1 = hash1(u);
        size_t h2 = hash2(fingerprint, h1);
        
        for(const auto &fp : table[h1])
            if(fp == fingerprint) return true;
        for(const auto &fp : table[h2])
            if(fp == fingerprint) return true;
        return false;
    }
    
    void remove(const string &u){ 
        uint8_t fingerprint = get_fingerprint(u);
        size_t h1 = hash1(u);
        size_t h2 = hash2(fingerprint, h1);
        
        auto &bucket1 = table[h1];
        auto it1 = find(bucket1.begin(), bucket1.end(), fingerprint);
        if(it1 != bucket1.end()){
            bucket1.erase(it1);
            return;
        }
        
        auto &bucket2 = table[h2];
        auto it2 = find(bucket2.begin(), bucket2.end(), fingerprint);
        if(it2 != bucket2.end()){
            bucket2.erase(it2);
        }
    }
    
    size_t memory_usage() const { 
        size_t total = 0;
        for(const auto &bucket : table){
            total += bucket.capacity() * sizeof(uint8_t); // 1 byte per fingerprint
        }
        return total;
    }
};

// ---------------------------- General Functions ----------------------------
template<typename T> void insert_bulk(T &checker,const vector<string> &names){ 
    for(auto &u:names) checker.insert(u); 
}

template<typename T> vector<bool> check_bulk(T &checker,const vector<string> &names){ 
    vector<bool> res; 
    for(auto &u:names) res.push_back(checker.search(u)); 
    return res; 
}

// ---------------------------- Interactive Mode ----------------------------
void interactive_mode_all(
    HashMapChecker &hm, BloomFilterChecker &bloom, CountingBloomChecker &cb,
    TrieChecker &trie, CuckooFilterChecker &cf,
    vector<string> &all_usernames, const string &outfile){

    vector<string> structure_names={"HashMap","Bloom","CountingBloom","Trie","Cuckoo"};
    vector<vector<bool>> structure_status={
        check_bulk(hm,all_usernames),
        check_bulk(bloom,all_usernames),
        check_bulk(cb,all_usernames),
        check_bulk(trie,all_usernames),
        check_bulk(cf,all_usernames)
    };

    string input;
    while(true){
        cout<<"\n" << string(70, '=') << "\n";
        cout<<"Enter username (or 'exit' to quit): ";
        cin>>input;
        if(input=="exit") break;

        cout << string(70, '-') << "\n";

        // Search latency and status
        vector<double> search_latency(5);
        vector<bool> found_status(5,false);

        found_status[0]=hm.search(input);
        search_latency[0]=measure_avg_ns([&]() { hm.search(input); }, 100, 1);

        found_status[1]=bloom.search(input);
        search_latency[1]=measure_avg_ns([&]() { bloom.search(input); }, 100, 1);

        found_status[2]=cb.search(input);
        search_latency[2]=measure_avg_ns([&]() { cb.search(input); }, 100, 1);

        found_status[3]=trie.search(input);
        search_latency[3]=measure_avg_ns([&]() { trie.search(input); }, 100, 1);

        found_status[4]=cf.search(input);
        search_latency[4]=measure_avg_ns([&]() { cf.search(input); }, 100, 1);

        cout << "\nSearch Results:\n";
        cout << left << setw(20) << "Data Structure" << setw(15) << "Status" << setw(15) << "Latency (ns)" << "\n";
        cout << string(50, '-') << "\n";
        for(int i=0;i<5;i++)
            cout << left << setw(20) << structure_names[i] 
                 << setw(15) << (found_status[i]?"Taken":"Available") 
                 << setw(15) << search_latency[i] << "\n";

        // Decide insert/delete option
        bool can_insert=false, can_delete=false;
        int idx = -1;
        auto it = find(all_usernames.begin(), all_usernames.end(), input);
        if(it!=all_usernames.end()) idx=it-all_usernames.begin();

        if(idx>=0){
            can_insert = false;
            for(int i=0;i<5;i++) if(!structure_status[i][idx]) can_insert=true;
            can_delete = true;
            for(int i=0;i<5;i++) if(!structure_status[i][idx]) can_delete=false;
        } else can_insert=true;

        if(can_insert){
            char choice; 
            cout << "\n➤ Username available in some data structures. Insert? (y/n): "; 
            cin>>choice;
            if(choice=='y'){
                vector<double> insert_latency(5);
                if(idx==-1){ all_usernames.push_back(input); idx=all_usernames.size()-1;
                    for(int i=0;i<5;i++) structure_status[i].push_back(false); }

                if(!structure_status[0][idx]) {
                    insert_latency[0]=measure_avg_ns([&]() { hm.insert(input); }, 100, 1);
                    structure_status[0][idx]=true;
                } else insert_latency[0]=0;

                if(!structure_status[1][idx]) {
                    insert_latency[1]=measure_avg_ns([&]() { bloom.insert(input); }, 100, 1);
                    structure_status[1][idx]=true;
                } else insert_latency[1]=0;

                if(!structure_status[2][idx]) {
                    insert_latency[2]=measure_avg_ns([&]() { cb.insert(input); }, 100, 1);
                    structure_status[2][idx]=true;
                } else insert_latency[2]=0;

                if(!structure_status[3][idx]) {
                    insert_latency[3]=measure_avg_ns([&]() { trie.insert(input); }, 100, 1);
                    structure_status[3][idx]=true;
                } else insert_latency[3]=0;

                if(!structure_status[4][idx]) {
                    insert_latency[4]=measure_avg_ns([&]() { cf.insert(input); }, 100, 1);
                    structure_status[4][idx]=true;
                } else insert_latency[4]=0;

                cout << "\nInsertion Latency:\n";
                cout << left << setw(20) << "Data Structure" << setw(15) << "Latency (ns)" << "\n";
                cout << string(35, '-') << "\n";
                for(int i=0;i<5;i++) 
                    cout << left << setw(20) << structure_names[i] << setw(15) << insert_latency[i] << "\n";

                write_results(outfile, all_usernames, structure_status, structure_names);
                cout << "\n✓ Username registered and output file updated.\n";
            }
        } else if(can_delete){
            char choice; 
            cout << "\n➤ Username exists in all data structures. Delete? (y/n): "; 
            cin>>choice;
            if(choice=='y'){
                vector<double> delete_latency(3);
                delete_latency[0]=measure_avg_ns([&]() { hm.remove(input); }, 100, 1);
                structure_status[0][idx]=false;

                delete_latency[1]=measure_avg_ns([&]() { cb.remove(input); }, 100, 1);
                structure_status[2][idx]=false;

                delete_latency[2]=measure_avg_ns([&]() { cf.remove(input); }, 100, 1);
                structure_status[4][idx]=false;

                cout << "\nDeletion Latency (structures with delete support):\n";
                cout << left << setw(20) << "Data Structure" << setw(15) << "Latency (ns)" << "\n";
                cout << string(35, '-') << "\n";
                cout << left << setw(20) << "HashMap" << setw(15) << delete_latency[0] << "\n";
                cout << left << setw(20) << "CountingBloom" << setw(15) << delete_latency[1] << "\n";
                cout << left << setw(20) << "Cuckoo" << setw(15) << delete_latency[2] << "\n";

                write_results(outfile, all_usernames, structure_status, structure_names);
                cout << "\n✓ Deletion applied and output file updated.\n";
            }
        } else {
            cout << "\n✗ No insertion or deletion allowed for this username.\n";
        }
    }
}

// ---------------------------- Main ----------------------------
int main(){
    vector<string> initial=read_usernames("usernames_input.txt");
    vector<string> queries=read_usernames("usernames_query.txt");
    
    // Create a set of initial usernames for fast lookup
    unordered_map<string, bool> initial_set;
    for(const auto &name : initial) {
        initial_set[name] = true;
    }
    
    // Split queries into existing (in initial) and new (not in initial)
    vector<string> existing_queries, new_queries;
    
    for(const auto &query : queries){
        if(initial_set.count(query)){
            existing_queries.push_back(query);
        } else {
            new_queries.push_back(query);
        }
    }
    
    // Insert ONLY initial usernames (not the new queries)
    vector<string> to_insert = initial;
    
    // All usernames for output
    vector<string> all_usernames = initial;
    string outfile="usernames_output.txt";

    HashMapChecker hm; 
    BloomFilterChecker bloom; 
    CountingBloomChecker cb; 
    TrieChecker trie; 
    CuckooFilterChecker cf;

    // Insert ONLY initial data (new queries should NOT be inserted)
    insert_bulk(hm, to_insert);
    insert_bulk(bloom, to_insert);
    insert_bulk(cb, to_insert);
    insert_bulk(trie, to_insert);
    insert_bulk(cf, to_insert);

    cout << "\n" << string(120, '=') << "\n";
    cout << "           USERNAME AVAILABILITY SYSTEM - BENCHMARK (100K Users Design)\n";
    cout << string(120, '=') << "\n\n";
    
    cout << "System Configuration (Modified for Demonstration):\n";
    cout << "  • Bloom Filter:          500K bits (~62.5 KB), 6 hash functions → Expected FP Rate: ~1-2%\n";
    cout << "  • Counting Bloom Filter: 600K counters (~586 KB), 6 hash functions → Expected FP Rate: ~0.5-1.5%\n";
    cout << "  • Cuckoo Filter:         150K buckets, 8-bit fingerprints, 4 entries/bucket → Expected FP Rate: ~0.5%\n";
    cout << "  • HashMap & Trie:        Deterministic (0% FP rate)\n\n";
    cout << "Dataset Configuration:\n";
    cout << "  • Inserted usernames:    " << to_insert.size() << " (from input file)\n";
    cout << "  • Total query usernames: " << queries.size() << "\n";
    cout << "  • Existing in dataset:   " << existing_queries.size() << " (" << fixed << setprecision(1) << (100.0 * existing_queries.size() / queries.size()) << "%)\n";
    cout << "  • New (not in dataset):  " << new_queries.size() << " (" << fixed << setprecision(1) << (100.0 * new_queries.size() / queries.size()) << "%) - for FP testing\n\n";
    cout << string(120, '=') << "\n\n";

    int total_inserted = to_insert.size();
    int total_queries = queries.size();

    // Get ground truth for FP calculation
    auto ground_truth = check_bulk(hm, queries);
    
    // Measure and display results
    vector<string> ds_names = {"HashMap", "Bloom Filter", "Counting Bloom", "Trie", "Cuckoo Filter"};
    vector<double> insert_latencies(5), search_latencies(5);
    vector<int> found_counts(5);
    vector<int> false_positives(5, 0);
    vector<double> fp_rates(5, 0.0);
    vector<size_t> memory_usage(5);

    cout << "Measuring insert latency..." << endl;
    insert_latencies[0] = measure_avg_ns([&]() { HashMapChecker temp; insert_bulk(temp, to_insert); }, 10, to_insert.size());

    insert_latencies[1] = measure_avg_ns([&]() { BloomFilterChecker temp; insert_bulk(temp, to_insert); }, 10, to_insert.size());

    insert_latencies[2] = measure_avg_ns([&]() { CountingBloomChecker temp; insert_bulk(temp, to_insert); }, 10, to_insert.size());

    insert_latencies[3] = measure_avg_ns([&]() { TrieChecker temp; insert_bulk(temp, to_insert); }, 10, to_insert.size());

    insert_latencies[4] = measure_avg_ns([&]() { CuckooFilterChecker temp; insert_bulk(temp, to_insert); }, 10, to_insert.size());



    cout << "Measuring search latency..." << endl;
    search_latencies[0] = measure_avg_ns([&]() { check_bulk(hm, queries); }, 100, queries.size());

    search_latencies[1] = measure_avg_ns([&]() { check_bulk(bloom, queries); }, 100, queries.size());

    search_latencies[2] = measure_avg_ns([&]() { check_bulk(cb, queries); }, 100, queries.size());

    search_latencies[3] = measure_avg_ns([&]() { check_bulk(trie, queries); }, 100, queries.size());

    search_latencies[4] = measure_avg_ns([&]() { check_bulk(cf, queries); }, 100, queries.size());

    // Get memory usage
    memory_usage[0] = hm.memory_usage();
    memory_usage[1] = bloom.memory_usage();
    memory_usage[2] = cb.memory_usage();
    memory_usage[3] = trie.memory_usage();
    memory_usage[4] = cf.memory_usage();

    // Count found items and calculate false positives
    auto res_hm = check_bulk(hm, queries); 
    auto res_bloom = check_bulk(bloom, queries);
    auto res_cb = check_bulk(cb, queries);
    auto res_trie = check_bulk(trie, queries);
    auto res_cf = check_bulk(cf, queries);
    
    int true_negatives = 0;
    for(size_t i = 0; i < queries.size(); i++){
        if(res_hm[i]) found_counts[0]++;
        if(res_bloom[i]) found_counts[1]++;
        if(res_cb[i]) found_counts[2]++;
        if(res_trie[i]) found_counts[3]++;
        if(res_cf[i]) found_counts[4]++;
        
        // Calculate false positives
        if(!ground_truth[i]){
            true_negatives++;
            if(res_bloom[i]) false_positives[1]++;
            if(res_cb[i]) false_positives[2]++;
            if(res_cf[i]) false_positives[4]++;
        }
    }
    
    // Calculate FP rates
    if(true_negatives > 0){
        for(int i = 0; i < 5; i++){
            fp_rates[i] = (false_positives[i] * 100.0) / true_negatives;
        }
    }

    // Display comprehensive table
    cout << left << setw(18) << "Data Structure"
         << setw(13) << "Insert (ns)"
         << setw(13) << "Search (ns)"
         << setw(16) << "Found/Queries"
         << setw(14) << "False Pos."
         << setw(11) << "FP Rate"
         << setw(13) << "Memory (KB)"
         << setw(13) << "Mem/User (B)" << "\n";
    cout << string(133, '-') << "\n";

    for(int i = 0; i < 5; i++){
        cout << left << setw(18) << ds_names[i]
             << setw(13) << fixed << setprecision(2) << insert_latencies[i]
             << setw(13) << fixed << setprecision(2) << search_latencies[i]
             << setw(16) << (to_string(found_counts[i]) + "/" + to_string(total_queries));

        if(i == 0 || i == 3){  // HashMap and Trie
            cout << setw(14) << "N/A" << setw(11) << "0.00%";
        } else {  // Probabilistic structures
            cout << setw(14) << (to_string(false_positives[i]) + "/" + to_string(true_negatives))
                 << setw(11) << fixed << setprecision(2) << fp_rates[i] << "%";
        }
        cout << setw(13) << fixed << setprecision(2) << (static_cast<double>(memory_usage[i]) / 1024.0)
             << setw(13) << fixed << setprecision(2) << (static_cast<double>(memory_usage[i]) / total_inserted) << "\n";
    }

    cout << "\n" << string(120, '=') << "\n";
    cout << "FILTER COMPARISON (Probabilistic Structures Only):\n";
    cout << string(120, '-') << "\n";
    cout << left << setw(22) << "Filter Type"
         << setw(18) << "Found/Queries"
         << setw(18) << "FP Count/Total"
         << setw(15) << "FP Rate"
         << setw(15) << "Memory (KB)"
         << setw(15) << "Mem/User (B)" << "\n";
    cout << string(135, '-') << "\n";
    
    cout << left << setw(22) << "Bloom Filter"
         << setw(18) << (to_string(found_counts[1]) + "/" + to_string(total_queries))
         << setw(18) << (to_string(false_positives[1]) + "/" + to_string(true_negatives))
         << setw(15) << fixed << setprecision(2) << fp_rates[1] << "%"
         << setw(15) << fixed << setprecision(2) << (static_cast<double>(memory_usage[1]) / 1024.0)
         << setw(15) << fixed << setprecision(2) << (static_cast<double>(memory_usage[1]) / total_inserted) << "\n";

    cout << left << setw(22) << "Counting Bloom Filter"
         << setw(18) << (to_string(found_counts[2]) + "/" + to_string(total_queries))
         << setw(18) << (to_string(false_positives[2]) + "/" + to_string(true_negatives))
         << setw(15) << fixed << setprecision(2) << fp_rates[2] << "%"
         << setw(15) << fixed << setprecision(2) << (static_cast<double>(memory_usage[2]) / 1024.0)
         << setw(15) << fixed << setprecision(2) << (static_cast<double>(memory_usage[2]) / total_inserted) << "\n";

    cout << left << setw(22) << "Cuckoo Filter"
         << setw(18) << (to_string(found_counts[4]) + "/" + to_string(total_queries))
         << setw(18) << (to_string(false_positives[4]) + "/" + to_string(true_negatives))
         << setw(15) << fixed << setprecision(2) << fp_rates[4] << "%"
         << setw(15) << fixed << setprecision(2) << (static_cast<double>(memory_usage[4]) / 1024.0)
         << setw(15) << fixed << setprecision(2) << (static_cast<double>(memory_usage[4]) / total_inserted) << "\n";

    cout << "\n" << string(120, '=') << "\n";
    cout << "Summary:\n";
    cout << "  • Total usernames inserted: " << total_inserted << "\n";
    cout << "  • Total queries performed:  " << total_queries << "\n";
    cout << "  • True negatives (absent):  " << true_negatives << "\n";
    cout << "  • True positives (present): " << (total_queries - true_negatives) << "\n";
    cout << string(120, '=') << "\n";

    write_results(outfile, all_usernames,
                  {check_bulk(hm,all_usernames),check_bulk(bloom,all_usernames),
                   check_bulk(cb,all_usernames),check_bulk(trie,all_usernames),
                   check_bulk(cf,all_usernames)},
                  {"HashMap","Bloom","CountingBloom","Trie","Cuckoo"});

    cout << "\n" << string(120, '=') << "\n";
    cout << "                              INTERACTIVE MODE\n";
    cout << string(120, '=') << "\n";
    interactive_mode_all(hm,bloom,cb,trie,cf,all_usernames,outfile);

    cout << "\nProgram terminated. Goodbye!\n";
    return 0;
}
