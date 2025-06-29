#pragma once


namespace firewall_core {
    // a rule node in tree structure
    struct TreeNode {
        Rule rule;
        u_short ruleID;
        std::vector<TreeNode*> children;

        TreeNode() {
            rule = Rule();
            ruleID = 0;
            children = std::vector<TreeNode*>();
        }

         size_t getChildrenSize() const { return children.size(); }
    };

    class RuleExecuter {
    public:
        RuleExecuter() { initRuleExecuter(); }
        ~RuleExecuter() { deleteRules(); }


        // ********************************************************************************
        /// <summary>
        /// function that matches packet to rules and determines the action to be taken based on rules
        /// </summary>
        /// <param name="packet"></param>
        /// <returns>action to be taken on a packet</returns>
        // ********************************************************************************
        std::pair<ndisapi::queued_packet_filter::packet_action, u_short> matchRules(const PacketInformation &packet);

        // ********************************************************************************
        /// <summary>
        /// function that print the rules in hierarchy(tree) type structure
        /// used for debugging purposes
        /// </summary>
        /// // ********************************************************************************
        void printExe() const;
        void printExe(TreeNode*, int) const;
    private:
        // ********************************************************************************
        /// <summary>
        /// initialize tree structure and loads rules
        /// </summary>
        /// <returns> true if success, false otherwise </returns>
        // ********************************************************************************
        bool initRuleExecuter();

        // ********************************************************************************
        /// <summary>
        /// loads the default rule into the tree structure
        /// default rule is to allow any packet
        /// </summary>
        /// <returns> true if success, false otherwise </returns>
        // ********************************************************************************
        bool buildDefaultRule();

        // ********************************************************************************
        /// <summary>
        /// laods the rule passed in the argument into the tree structure
        /// </summary>
        /// <param name="rule"> rule to be laoded </param>
        /// <returns> true if success, false otherwise </returns>
        /// // ********************************************************************************
        bool buildRule(const Rule& rule);

        // ********************************************************************************
        /// <summary>
        /// deletes every rule from tree structure
        /// </summary>
        /// <returns> true if success, false otherwise </returns>
        /// // ********************************************************************************
        bool deleteRules();
        bool deleteRules(TreeNode* root);
        
        ///<summary> ptr to a root of the tree structure </summary>
        TreeNode* treeRoot;
        ///<summary> maps PROTOCOl to its index in roots->children </summary>
        std::map<u_char, u_short> protoIndex;
        /// <summary> stores default rule address (proto, srcIp, destIp, etc.) </summary>
        std::vector<TreeNode*> defaultRule;
        /// <summary> current # of ID's (sequantial ID) </summary>
        u_short currentId = 0;
        /// <summary> max number of rules allowed which 65535 </summary>
        const u_short MAX_RULES = 0xffff;
    };

    inline bool RuleExecuter::initRuleExecuter() {
        treeRoot = new TreeNode();
        buildDefaultRule();

        //temporary RULEs
        std::vector<Rule> rules = { Rule(1,ANY_PROTO, ANY_IP, ANY_IP,ANY_PORT, 80, ndisapi::queued_packet_filter::packet_action::drop),
                                    Rule(2,ANY_PROTO, ANY_IP, ANY_IP,ANY_PORT, ANY_PORT, ndisapi::queued_packet_filter::packet_action::drop),
                                    Rule(3,ANY_PROTO, "8.8.8.8", ANY_IP,ANY_PORT, ANY_PORT, ndisapi::queued_packet_filter::packet_action::pass),
                                    Rule(4,IPPROTO_UDP, ANY_IP, ANY_IP,ANY_PORT, 8080, ndisapi::queued_packet_filter::packet_action::drop),
                                    Rule(5,IPPROTO_TCP, ANY_IP, ANY_IP,ANY_PORT, 8080, ndisapi::queued_packet_filter::packet_action::pass),
                                    Rule(6,IPPROTO_TCP, "216.239.32.21", ANY_IP,ANY_PORT, 8080, ndisapi::queued_packet_filter::packet_action::pass),
                                    /*black listed IPs*/
                                    Rule(7,ANY_PROTO, "12.36.233.53", ANY_IP,ANY_PORT, ANY_PORT, ndisapi::queued_packet_filter::packet_action::drop),
                                    Rule(8,ANY_PROTO, "24.19.232.156", ANY_IP,ANY_PORT, ANY_PORT, ndisapi::queued_packet_filter::packet_action::drop),
                                    Rule(9,ANY_PROTO, "12.235.186.202", ANY_IP,ANY_PORT, ANY_PORT, ndisapi::queued_packet_filter::packet_action::drop),
                                    Rule(10,ANY_PROTO, "16.98.105.52", ANY_IP,ANY_PORT, ANY_PORT, ndisapi::queued_packet_filter::packet_action::drop),
                                    Rule(11,ANY_PROTO, "23.116.86.82", ANY_IP,ANY_PORT, ANY_PORT, ndisapi::queued_packet_filter::packet_action::drop),
                                    Rule(12,ANY_PROTO, "24.8.36.247", ANY_IP,ANY_PORT, ANY_PORT, ndisapi::queued_packet_filter::packet_action::drop),
                                    Rule(13,ANY_PROTO, "24.10.151.118", ANY_IP,ANY_PORT, ANY_PORT, ndisapi::queued_packet_filter::packet_action::drop),
                                    Rule(14,ANY_PROTO, "35.151.139.129", ANY_IP,ANY_PORT, ANY_PORT, ndisapi::queued_packet_filter::packet_action::drop),
                                    Rule(15,ANY_PROTO, "50.27.173.66", ANY_IP,ANY_PORT, ANY_PORT, ndisapi::queued_packet_filter::packet_action::drop) };
     
        try {
            for (auto& i : rules) {
                buildRule(i);
            }
        }
        catch (std::exception& e) {
            std::cerr << "Exception occured: " << e.what() << std::endl;
            return false;
        }

        return true;
    }

    inline bool RuleExecuter::buildDefaultRule() {
        protoIndex[ANY_PROTO] = 0;
        TreeNode* it = treeRoot;

        defaultRule = std::vector<TreeNode*>(5);

        for (int i = 0; i < 5; i++) {
            it->children.push_back(new TreeNode);
            it = it->children[0];
            defaultRule[i] = it;
        }
        it->ruleID = 0; //default rule id = 0

        return true;
    }

    inline bool RuleExecuter::buildRule(const Rule &rule) {
        //if we exceeded the limit number of rules
        if (currentId == MAX_RULES) {
            throw std::runtime_error("Exceeded rules limit");
            return false;
        }


        //protocol has not been initialized yet
        TreeNode* it = treeRoot;

        if (protoIndex.find(rule.proto) == protoIndex.end()) {
            //set the index of specifc protocol
            protoIndex[rule.proto] = (u_short)it->getChildrenSize();
            it->children.push_back(new TreeNode());
            it->children[it->getChildrenSize() - 1]->rule.proto = rule.proto;
        }
        it = it->children[protoIndex[rule.proto]];


        //src ip
        bool found = false;
        for (auto& i : it->children) {
            //if the src IP has been initialized before
            if (i->rule.srcIP == rule.srcIP) {
                found = true;
                it = i;
                break;
            }
        }
        if (!found) {  //create new node incase not found
            it->children.push_back(new TreeNode());
            it = it->children[it->getChildrenSize() - 1];
            it->rule.srcIP = rule.srcIP;
        }

        //dest ip
        found = false;
        for (auto& i : it->children) {
            if (i->rule.destIP == rule.destIP) {
                found = true;
                it = i;
                break;
            }
        }
        if (!found) {
            it->children.push_back(new TreeNode());
            it = it->children[it->getChildrenSize() - 1];
            it->rule.destIP = rule.destIP;
        }

        //src port
        found = false;
        for (auto& i : it->children) {
            if (i->rule.srcPort == rule.srcPort) {
                found = true;
                it = i;
                break;
            }
        }
        if (!found) {
            it->children.push_back(new TreeNode());
            it = it->children[it->getChildrenSize() - 1];
            it->rule.srcPort = rule.srcPort;
        }

        //dest port
        found = false;
        for (auto& i : it->children) {
            if (i->rule.destPort == rule.destPort) {
                found = true;
                it = i;
                break;
            }
        }
        if (!found) {
            it->children.push_back(new TreeNode());
            it = it->children[it->getChildrenSize() - 1];
            it->rule.destPort = rule.destPort;
        }

        //determine the action
        it->rule.action = rule.action;
        //assign rule id
        it->ruleID = ++currentId;
        return true;
    }

    inline bool RuleExecuter::deleteRules() {
        deleteRules(treeRoot);
        currentId = 0;
        return true;
    }
    inline bool RuleExecuter::deleteRules(TreeNode* root) {
        for (auto& i : root->children) {
            deleteRules(i);
        }
        delete root;

        return true;
    }

    inline std::pair<ndisapi::queued_packet_filter::packet_action, u_short> RuleExecuter::matchRules(const PacketInformation &packet) {
        TreeNode* curr = treeRoot;

        try {
            //Level 1 -> match protocol
            //if it has no node: go to default
            if (protoIndex.find(packet.proto) == protoIndex.end())
                curr = defaultRule[0];
            else
                curr = curr->children[protoIndex[packet.proto]];

            //exception handling
            if (!curr) throw std::runtime_error("Level 1 is null");

            //Level 2 -> match source IP
            bool exist = false;
            bool any = false;
            TreeNode* anyNode = NULL;
            for (auto& i : curr->children) {
                if (i->rule.srcIP == packet.srcIP) {
                    curr = i;
                    exist = true;
                    break;
                }
                else if (i->rule.srcIP == ANY_IP) {
                    any = true;
                    anyNode = i;
                }
            }
            if (!exist) curr = (any)? anyNode : defaultRule[1];  //go to default source ip node

            //exception handling
            if (!curr) throw std::runtime_error("Level 2 is null");

            //Level 3 -> match destination IP
            exist = false;
            any = false;
            anyNode = NULL;
            for (auto& i : curr->children) {
                if (i->rule.destIP == packet.destIP) {
                    curr = i;
                    exist = true;
                    break;
                }
                else if (i->rule.destIP == ANY_IP) {
                    any = true;
                    anyNode = i;
                }
            }
            if (!exist) curr = (any) ? anyNode : defaultRule[2];  //go to default/any destination ip node

            //exception handling
            if (!curr) throw std::runtime_error("Level 3 is null");

          
            //Level 4 -> match source Port
            exist = false;
            any = false;
            anyNode = NULL;
            for (auto& i : curr->children) {
                if (i->rule.srcPort == packet.srcPort) {
                    curr = i;
                    exist = true;
                    break;
                }
                else if (i->rule.srcPort == ANY_PORT) {
                    any = true;
                    anyNode = i;
                }
            }
            if (!exist) curr = (any) ? anyNode : defaultRule[3];  //go to default/any source Port node

            //exception handling
            if (!curr) throw std::runtime_error("Level 4 is null");

            //Level 5 (last) -> match destination Port
            exist = false;
            any = false;
            anyNode = NULL;
            for (auto& i : curr->children) {
                if (i->rule.destPort == packet.destPort) {
                    curr = i;
                    exist = true;
                    break;
                }
                else if (i->rule.destPort == ANY_PORT) {
                    any = true;
                    anyNode = i;
                }
            }
            if (!exist) curr = (any) ? anyNode : defaultRule[4];  //go to default/any destination Port node
            
            //exception handling
            if (!curr) throw std::runtime_error("Level 5 is null");
        }
        catch (const std::exception &e) {
            std::cerr << "Exception occured: " << e.what() << std::endl;
            return { ndisapi::queued_packet_filter::packet_action::drop, 0xffff };
        }

        return { curr->rule.action, curr->ruleID };
    }

    //functions for debugging purposes
    inline void RuleExecuter::printExe() const{
        TreeNode* curr = treeRoot;
        std::cout << "ROOT:" << std::endl;
        for (auto& i : curr->children) {
            std::cout << "lvl=0->";
            std::cout << ntohs(i->rule.proto) << '/' << i->rule.srcIP << '/' << i->rule.destIP << '/';
            std::cout << i->rule.srcPort << '/' << i->rule.destPort << '/';
            if (i->rule.action == ndisapi::queued_packet_filter::packet_action::pass)
                std::cout << "pass" << std::endl;
            else if (i->rule.action == ndisapi::queued_packet_filter::packet_action::drop)
                std::cout << "drop" << std::endl;
            else std::cout << "revert" << std::endl;

            printExe(i, 1);
        }
    }

    inline void RuleExecuter::printExe(TreeNode* root, int lvl) const {
        TreeNode* curr = root;
        for (auto& i : curr->children) {
            std::cout << "lvl=" << lvl;
            for (int num = 0; num < lvl; num++) std::cout << "  ";
            std::cout << "->";
            std::cout << ntohs(i->rule.proto) << '/' << i->rule.srcIP << '/' << i->rule.destIP << '/';
            std::cout << i->rule.srcPort << '/' << i->rule.destPort << '/';
            if (i->rule.action == ndisapi::queued_packet_filter::packet_action::pass)
                std::cout << "pass" << std::endl;
            else if (i->rule.action == ndisapi::queued_packet_filter::packet_action::drop)
                std::cout << "drop" << std::endl;
            else std::cout << "revert" << std::endl;

            printExe(i, lvl+1);
        }
    }
}