# Client Demo Meeting Guide
**Date:** Wednesday  
**Team:** Malyk, Jaimee, Daniel  
**Purpose:** Share updates and demo the Bio-ISAC Vulnerability Triage Bot

---

## 📋 Meeting Structure (30-45 minutes)

### 1. Introduction & Agenda (2-3 min)
### 2. Project Overview (5 min)
### 3. Live Demo (15-20 min)
### 4. Technical Deep Dive (5-7 min)
### 5. Q&A & Discussion (10-15 min)

---

## 👥 Role Assignments

### **Malyk** (Lead Developer)
**Responsibilities:**
- Opening introduction & agenda
- Live Slack demo (primary)
- Technical architecture explanation
- Database & infrastructure overview
- Answering technical questions

**Key Talking Points:**
- "We've built a production-ready Slack bot that runs 24/7 on Heroku"
- "The system automatically fetches vulnerability data daily and scores it for bio-industry relevance"
- "We've implemented customizable digests so different service lines can see what's relevant to them"

### **Jaimee** (Feature Presenter)
**Responsibilities:**
- Project overview & use cases
- Feature walkthrough (backup demo)
- User experience & workflow explanation
- Customizable digest feature demo
- Business value discussion

**Key Talking Points:**
- "This helps security teams prioritize vulnerabilities without leaving their workflow"
- "The bot provides actionable intelligence with severity ratings and recommended actions"
- "Different teams can customize their daily digests to focus on their specific areas"

### **Daniel** (Support & Q&A)
**Responsibilities:**
- Monitor chat/questions during demo
- Handle follow-up questions
- Document client feedback
- Discuss future enhancements
- Ask strategic questions to client

**Key Talking Points:**
- "We're looking for feedback on what features would be most valuable"
- "How does this fit into your current security workflow?"
- "What additional data sources or integrations would be helpful?"

---

## 🎬 Demo Script

### **Opening (Malyk - 2 min)**
"Thanks for meeting with us today! We're excited to show you the progress we've made on the Bio-ISAC vulnerability triage bot. 

**What we'll cover:**
1. Quick overview of what we've built
2. Live demo of the bot in action
3. Technical architecture
4. Q&A and discussion about next steps

Let's jump in!"

---

### **Project Overview (Jaimee - 5 min)**

**The Problem:**
"Security teams are overwhelmed with vulnerability data from multiple sources. It's hard to prioritize what matters for the bio-industry specifically."

**Our Solution:**
"We built a Slack bot that:
- Automatically ingests data from NVD (National Vulnerability Database) and CISA KEV (Known Exploited Vulnerabilities)
- Scores vulnerabilities for bio-industry relevance using a custom algorithm
- Provides real-time intelligence directly in Slack
- Sends daily digests with prioritized threats"

**Key Features:**
- ✅ Real-time vulnerability queries via Slack commands
- ✅ Bio-relevance scoring (0-10 scale)
- ✅ Daily automated digests
- ✅ Customizable filters for different service lines
- ✅ Severity classification with color coding
- ✅ Actionable recommendations for each vulnerability

**Value Proposition:**
- Saves time - no need to leave Slack
- Prioritizes what matters - bio-relevance scoring
- Actionable - includes recommended actions and advisory links
- Customizable - each team can see what's relevant to them

---

### **Live Demo (Malyk - 15-20 min)**

**Setup:**
- Have Slack open with the bot ready
- Have Heroku dashboard open in another tab (for technical questions)
- Prepare example CVEs to search

**Demo Flow:**

1. **Basic Commands (3-4 min)**
   - `/bioisac help` - Show command reference
   - `/bioisac top` - Show top 10 vulnerabilities
   - Explain: "These are ranked by our bio-relevance scoring algorithm"
   - Point out: Severity badges (🔴🟠🟡🟢), priority indicators (KEV, Medical, ICS)

2. **Search Functionality (2-3 min)**
   - `/bioisac search <vendor>` - Search for a specific vendor
   - `/bioisac detail <CVE-ID>` - Show detailed vulnerability info
   - Explain: "You can search by vendor, product, or CVE ID"

3. **Stats & Analytics (2 min)**
   - `/bioisac stats` - Show database statistics
   - Explain: "This gives you an overview of what we're monitoring"

4. **Recent Vulnerabilities (2 min)**
   - `/bioisac recent 48` - Show vulnerabilities from last 48 hours
   - Explain: "Great for daily triage and staying on top of new threats"

5. **NEW: Customizable Digests (4-5 min)**
   - `/bioisac digest-setup` - Show help
   - `/bioisac digest-setup set medical cvss-min:7.0` - Set preference
   - `/bioisac digest-setup show` - Show current preferences
   - Explain: "This is our newest feature - each user can customize what they see in their daily digest based on their service line"

**Demo Tips:**
- Go slow - let them see the responses
- Explain what you're doing as you do it
- Point out key features (severity badges, priority indicators, advisory links)
- If something doesn't work, have backup examples ready

---

### **Technical Deep Dive (Malyk - 5-7 min)**

**Architecture Overview:**
- "The bot runs on Heroku as a production service - it's always available"
- "We use a MySQL database (JawsDB) to store vulnerability data"
- "ETL process runs daily to fetch new data from NVD and CISA KEV"
- "Everything is automated - no manual intervention needed"

**Data Flow:**
1. ETL fetches data from NVD API and CISA KEV
2. Data is normalized and scored for bio-relevance
3. Stored in database with tags (Medical, ICS, Bio-keywords, KEV)
4. Bot queries database when users run commands
5. Daily digest automatically posts to configured channels

**Scoring Algorithm:**
- KEV (Known Exploited) = +3 points
- ICS-related = +2 points
- Medical devices = +2 points
- High CVSS (≥8.0) = +1 point
- Recent (published within 14 days) = +1 point
- Bio-keywords = +1 point
- Maximum score: 10 points

**Production Setup:**
- Heroku worker dyno (runs 24/7)
- Heroku Scheduler (runs ETL and digest automatically)
- GitHub integration (automatic deploys)
- Database: JawsDB MySQL (upgraded plan for better performance)

---

## 💬 Potential Client Questions & Answers

### **Security & Access Control**

**Q: How do you control who can access the bot?**
A: "We have configurable access control via environment variables. You can whitelist specific Slack users or channels. If no restrictions are set, anyone in your workspace can use it. Access changes can be made through Heroku config vars and take effect automatically."

**Q: Is the data secure?**
A: "Yes. The database is hosted on Heroku's secure infrastructure. All connections use encrypted protocols. Environment variables (tokens, credentials) are stored securely in Heroku config vars, not in code."

### **Scalability & Performance**

**Q: Can this handle a large number of users?**
A: "Yes. The bot is stateless and can handle multiple concurrent requests. The database is designed to scale, and we're using an upgraded JawsDB plan that supports higher query volumes. If needed, we can scale the Heroku dyno or upgrade the database plan."

**Q: What happens if the bot goes down?**
A: "Heroku automatically restarts the bot if it crashes. We also have error handling throughout the codebase. For monitoring, you can check the Heroku dashboard or view logs in real-time."

### **Data Sources & Accuracy**

**Q: Where does the vulnerability data come from?**
A: "We pull from two primary sources:
- NVD (National Vulnerability Database) - the official CVE database
- CISA KEV (Known Exploited Vulnerabilities) - actively exploited vulnerabilities
Both are authoritative government sources that security teams trust."

**Q: How often is the data updated?**
A: "The ETL runs daily at 7:00 AM UTC, fetching CVEs modified in the last 7 days (configurable). This ensures you're always seeing the latest vulnerability information. The process is incremental, so it updates existing CVEs and adds new ones."

**Q: How accurate is the bio-relevance scoring?**
A: "The scoring algorithm uses keyword matching and industry-standard flags (ICS, Medical, KEV). It's designed to prioritize vulnerabilities that are most likely to affect bio-industry infrastructure. The scoring is transparent - you can see why each vulnerability scored what it did based on the flags."

### **Customization & Integration**

**Q: Can we customize the scoring algorithm?**
A: "Currently, the algorithm is fixed, but the weights and keywords are configurable in the code. We could adjust the scoring based on your specific needs. The customizable digest feature allows users to filter results, which provides some flexibility."

**Q: Can this integrate with other tools?**
A: "The bot is built on Slack's platform, so it integrates naturally with Slack workflows. We could potentially add webhooks to send data to other systems, or create API endpoints if needed. What integrations are you thinking about?"

**Q: Can we add our own data sources?**
A: "Yes! The architecture is designed to be extensible. We have hooks for EUVD (European Vulnerability Database) that aren't active yet. We could add other sources like vendor advisories or internal vulnerability databases."

### **Maintenance & Support**

**Q: Who maintains this?**
A: "Currently, our team maintains it. The system is designed to run automatically with minimal intervention. Daily operations (ETL, digests) happen automatically. Code updates can be deployed via GitHub, which triggers automatic deploys to Heroku."

**Q: What's the ongoing cost?**
A: "Heroku hosting costs approximately $17/month (worker dyno + database). The NVD API is free. CISA KEV is free. There are no per-user or per-query charges."

**Q: What happens after the project ends?**
A: "The bot will continue running on Heroku as long as the account is active. You'd need to maintain the Heroku account and config vars. We can provide documentation for handoff, or discuss a transition plan."

### **Features & Functionality**

**Q: Can we add more commands?**
A: "Absolutely! The bot framework makes it easy to add new commands. What functionality are you interested in?"

**Q: Can we export data or generate reports?**
A: "Currently, the bot displays data in Slack. We could add export functionality or create scheduled reports. What format would be most useful - CSV, PDF, email?"

**Q: How do we know if a vulnerability affects our specific systems?**
A: "The bot shows vendor/product information for each CVE. You can search by your specific vendors/products. We could potentially add asset inventory integration to automatically match CVEs to your systems."

---

## ❓ Questions to Ask the Client

### **Feature Priorities & Needs**

1. **"What features would be most valuable for your security team?"**
   - Helps prioritize development
   - Identifies gaps in current functionality

2. **"Are there specific vendors or products you want us to prioritize in the scoring?"**
   - Can adjust keyword lists
   - Can add vendor-specific logic

3. **"What's your current process for vulnerability triage, and how does this fit in?"**
   - Understand workflow integration
   - Identify pain points to solve

4. **"Do you have other vulnerability data sources we should integrate?"**
   - Vendor advisories
   - Internal databases
   - Other threat intelligence feeds

### **User Experience & Adoption**

5. **"How many users would be using this bot?"**
   - Helps plan for scale
   - Understands user base

6. **"What channels or teams would benefit most from this?"**
   - Helps configure digest channels
   - Identifies use cases

7. **"Are there specific reporting or analytics needs?"**
   - Metrics dashboards
   - Executive summaries
   - Compliance reporting

### **Technical & Integration**

8. **"Do you have existing security tools we should integrate with?"**
   - SIEM systems
   - Ticketing systems
   - Asset management

9. **"What's your preferred deployment model - cloud (Heroku) or on-premises?"**
   - Current setup is cloud
   - Could discuss alternatives

10. **"Are there compliance or security requirements we need to meet?"**
    - Data retention policies
    - Access logging
    - Audit trails

### **Future Development**

11. **"What would make this tool indispensable for your team?"**
    - Identifies must-have features
    - Helps roadmap planning

12. **"Are there other use cases beyond vulnerability triage we should consider?"**
    - Threat intelligence
    - Incident response
    - Risk assessment

13. **"What's your timeline for full deployment/adoption?"**
    - Helps plan development sprints
    - Sets expectations

### **Feedback & Iteration**

14. **"What concerns or questions do you have about the current implementation?"**
    - Addresses hesitations
    - Opens dialogue

15. **"How would you like to provide feedback as we continue development?"**
    - Establishes communication channel
    - Sets feedback process

---

## 🎯 Demo Success Criteria

**What we want to achieve:**
- ✅ Client understands what the bot does and how it works
- ✅ Client sees the value for their security team
- ✅ Client provides feedback on priorities
- ✅ We identify next steps and timeline
- ✅ Client feels confident in the project's direction

**Red flags to watch for:**
- Client seems confused about functionality
- Client asks "why would we need this?" (we didn't explain value well)
- Client has major concerns we can't address
- Client wants features that are way out of scope

**If things go wrong:**
- Have backup demo examples ready
- If Slack is down, show Heroku dashboard and explain architecture
- If questions are too technical, offer to follow up with documentation
- Always bring it back to business value

---

## 📝 Post-Meeting Action Items Template

**What we learned:**
- [ ] Feature priorities: _______________
- [ ] Integration needs: _______________
- [ ] User feedback: _______________
- [ ] Concerns to address: _______________

**Next steps:**
- [ ] Follow up on: _______________
- [ ] Research: _______________
- [ ] Implement: _______________
- [ ] Schedule next meeting: _______________

**Questions to research:**
- [ ] _______________
- [ ] _______________

---

## 💡 Pro Tips

1. **Practice the demo beforehand** - Know your examples and have backups
2. **Have the Heroku dashboard ready** - Shows it's production-ready
3. **Be honest about limitations** - Builds trust
4. **Focus on business value** - Not just technical features
5. **Listen actively** - Client feedback is gold
6. **Take notes** - Daniel should document everything
7. **End with clear next steps** - Don't leave them hanging

---

## 🚀 Closing Statement (Malyk)

"Thanks for your time today! We're really excited about this project and think it can make a real difference for your security team. 

**What's next:**
- We'll incorporate your feedback
- Continue refining features based on your priorities
- Keep you updated on progress

**Questions or feedback?** Feel free to reach out anytime. We're here to make this work for you!"

---

Good luck with the demo! 🎉

