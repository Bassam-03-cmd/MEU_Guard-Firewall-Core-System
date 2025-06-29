#pragma once
namespace firewall_core {

    struct Node {
        Rule rule;
        Node* next;

        Node() {
            rule = Rule();
            next = NULL;
        }
        Node(const Rule &r) {
            rule = r;
            next = NULL;
        }
    };

    class LinearRuleExecuter {
    public:
        LinearRuleExecuter() { initRuleExecuter(); }
        ~LinearRuleExecuter() { deleteRules(); }


        // ********************************************************************************
        /// <summary>
        /// function that matches packet to rules (lineary) and determines the action to be taken based on a rule
        /// </summary>
        /// <param name="packet"></param>
        /// <returns> action to be taken on a packet and rule id</returns>
        // ********************************************************************************
        std::pair<PACKET_ACTION, u_short> matchRules(const PacketInformation& packet);

        // ********************************************************************************
        /// <summary>
        /// laods the rule passed in the argument into the linked list structure
        /// </summary>
        /// <param name="rule"> rule to be laoded </param>
        /// <returns> true if success, false otherwise </returns>
        /// // ********************************************************************************
        bool addRule(const Rule& rule);

        // ********************************************************************************
        /// <summary>
        /// lineary searches for the rule by id and deletes it from the linked list
        /// </summary>
        /// <param name="id"></param>
        /// <returns> true if the rule were deleted, false otherwise </returns>
        // ********************************************************************************
        bool deleteRuleById(const u_int id);

        // ********************************************************************************
        /// <summary>
        /// function that print the rules in hierarchy(tree) type structure
        /// used for debugging purposes
        /// </summary>
        /// // ********************************************************************************
        void printExe() const;
    private:
        // ********************************************************************************
        /// <summary>
        /// initialize the executer (loads the rules into linked list)
        /// </summary>
        /// <returns> true if success, false otherwise </returns>
        // ********************************************************************************
        bool initRuleExecuter();

        // ********************************************************************************
        /// <summary>
        /// deletes every rule from the linked list
        /// </summary>
        /// <returns> true if success, false otherwise </returns>
        /// // ********************************************************************************
        bool deleteRules();

        ///<summary> ptr to a root of the linked list and the rear </summary>
        Node* root, *rear;

        /// <summary> max number of rules allowed which 65535 </summary>
        const u_short MAX_RULES = 0xffff;
        /// <summary> the current size of the linked list</summary>
        u_short size = 0;
    };

    inline bool LinearRuleExecuter::initRuleExecuter() {
        root = rear = NULL;

        database::RuleDAO ruleDAO;
        std::vector<Rule> rules = ruleDAO.getAllRules();
        
        
        //temporary RULEs
        /*std::vector<Rule> rules = {Rule(1,ANY_PROTO, ANY_IP, ANY_IP,ANY_PORT, 80, ndisapi::queued_packet_filter::packet_action::drop),
                                  Rule(2,ANY_PROTO, ANY_IP, ANY_IP,ANY_PORT, ANY_PORT, ndisapi::queued_packet_filter::packet_action::drop),
                                  Rule(3,ANY_PROTO, "8.8.8.8", ANY_IP,ANY_PORT, ANY_PORT, ndisapi::queued_packet_filter::packet_action::pass),
                                  Rule(4,IPPROTO_UDP, ANY_IP, ANY_IP,ANY_PORT, 8080, ndisapi::queued_packet_filter::packet_action::drop),
                                  Rule(5,IPPROTO_TCP, ANY_IP, ANY_IP,ANY_PORT, 8080, ndisapi::queued_packet_filter::packet_action::pass),
                                  Rule(6,IPPROTO_TCP, "216.239.32.21", ANY_IP,ANY_PORT, 8080, ndisapi::queued_packet_filter::packet_action::pass),
            Rule(7,ANY_PROTO, "12.36.233.53", ANY_IP,ANY_PORT, ANY_PORT, ndisapi::queued_packet_filter::packet_action::drop),
            Rule(8,ANY_PROTO, "24.19.232.156", ANY_IP,ANY_PORT, ANY_PORT, ndisapi::queued_packet_filter::packet_action::drop),
            Rule(9,ANY_PROTO, "12.235.186.202", ANY_IP,ANY_PORT, ANY_PORT, ndisapi::queued_packet_filter::packet_action::drop),
            Rule(10,ANY_PROTO, "16.98.105.52", ANY_IP,ANY_PORT, ANY_PORT, ndisapi::queued_packet_filter::packet_action::drop),
            Rule(11,ANY_PROTO, "23.116.86.82", ANY_IP,ANY_PORT, ANY_PORT, ndisapi::queued_packet_filter::packet_action::drop),
            Rule(12,ANY_PROTO, "24.8.36.247", ANY_IP,ANY_PORT, ANY_PORT, ndisapi::queued_packet_filter::packet_action::drop),
            Rule(13,ANY_PROTO, "24.10.151.118", ANY_IP,ANY_PORT, ANY_PORT, ndisapi::queued_packet_filter::packet_action::drop),
            Rule(14,ANY_PROTO, "35.151.139.129", ANY_IP,ANY_PORT, ANY_PORT, ndisapi::queued_packet_filter::packet_action::drop),
            Rule(15,ANY_PROTO, "50.27.173.66", ANY_IP,ANY_PORT, ANY_PORT, ndisapi::queued_packet_filter::packet_action::drop) };
        */

        for (auto const &i : rules) {
            try {
                addRule(i);
            }
            catch (std::exception& e) {
                std::cerr << "Exception occured: " << e.what() << std::endl;
            }
        }

        return true;
    }

    inline bool LinearRuleExecuter::addRule(const Rule& rule) {
        if (!root) root = rear = new Node(rule);
        else {
            //if there are more rules that the limit
            if (size == MAX_RULES) {
                throw std::runtime_error("Exceeded rules limit");
                return false;
            }

            rear->next = new Node(rule);
            rear = rear->next;
            size++;
        }

        return true;
    }

    inline bool LinearRuleExecuter::deleteRules() {
        while (root) {
            Node* crnt = root;
            root = root->next;
            delete crnt;
        }

        root = rear = NULL;
        size = 0;
        return true;
    }

    inline std::pair<PACKET_ACTION, u_short> LinearRuleExecuter::matchRules(const PacketInformation& packet) {
        Node* crnt = root;
        while (crnt) {

            if (crnt->rule.match(packet)) 
                return { crnt->rule.action, crnt->rule.id };
            crnt = crnt->next;
        }

        //default rule
        return { PACKET_ACTION::pass, 0};
    }

    inline bool LinearRuleExecuter::deleteRuleById(const u_int id) {
        Node *crnt = root, *prev = NULL;
        while (crnt) {
            if (crnt->rule.id == id) {
                //if we delete the first element
                if (crnt == root) 
                    root = root->next;
                else 
                    prev->next = crnt->next;

                if (crnt == rear) rear = prev;
                delete crnt;
                size--;
                return true;
            }

            prev = crnt;
            crnt = crnt->next;
        }

        //couldnt find the rule with the id = 'id'
        return false;
    }


    //functions for debugging purposes
    inline void LinearRuleExecuter::printExe() const {
        Node* crnt = root;
        while (crnt) {
            std::cout << "{";
            crnt->rule.print();
            std::cout<< "}->";
            crnt = crnt->next;
        }
        std::cout << "NULL\n";
    }
}