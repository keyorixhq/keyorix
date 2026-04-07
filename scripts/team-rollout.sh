#!/bin/bash

# Task 9: Team Rollout Script
# Prepares the system for team-wide deployment and adoption

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo "🚀 Keyorix Team Rollout Preparation"
echo "===================================="

# Create rollout directories
log_info "Setting up rollout infrastructure..."
mkdir -p rollout/{staging,training,feedback,announcements}

# Create staging environment configuration
log_info "Creating staging environment..."
cat > rollout/staging/docker-compose.staging.yml << 'EOF'
version: '3.8'

services:
  keyorix-staging:
    build: ../../server
    ports:
      - "8081:8080"
    environment:
      - KEYORIX_ENV=staging
      - KEYORIX_DB_URL=sqlite:///data/keyorix-staging.db
      - KEYORIX_LOG_LEVEL=debug
    volumes:
      - staging-data:/data
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  nginx-staging:
    image: nginx:alpine
    ports:
      - "8082:80"
    volumes:
      - ../../web/dist:/usr/share/nginx/html
      - ./nginx-staging.conf:/etc/nginx/nginx.conf
    depends_on:
      - keyorix-staging

volumes:
  staging-data:
EOF

# Create staging nginx configuration
cat > rollout/staging/nginx-staging.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    upstream keyorix_staging {
        server keyorix-staging:8080;
    }

    server {
        listen 80;
        server_name staging.keyorix.local;

        # Serve static web files
        location / {
            root /usr/share/nginx/html;
            try_files $uri $uri/ /index.html;
        }

        # Proxy API requests
        location /api/ {
            proxy_pass http://keyorix_staging;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        # Health check
        location /health {
            proxy_pass http://keyorix_staging;
        }

        # Swagger documentation
        location /swagger/ {
            proxy_pass http://keyorix_staging;
        }
    }
}
EOF

# Create team training materials
log_info "Creating team training materials..."
cat > rollout/training/team-training-plan.md << 'EOF'
# Team Training Plan for Keyorix

## Training Schedule

### Week 1: Introduction and Setup
**Target Audience**: All team members
**Duration**: 2 hours
**Format**: Live presentation + hands-on

#### Session 1: Introduction to Keyorix (1 hour)
- What is secret management and why it matters
- Overview of Keyorix features and capabilities
- Security benefits and best practices
- Q&A session

#### Session 2: Getting Started (1 hour)
- Account setup and first login
- Creating and managing secrets
- Basic sharing and collaboration
- Web dashboard walkthrough

### Week 2: Advanced Features
**Target Audience**: Power users and admins
**Duration**: 1.5 hours
**Format**: Workshop

#### Advanced Secret Management
- Secret types and metadata
- Bulk operations and organization
- Search and filtering techniques
- Version history and rollback

#### Collaboration Features
- Team sharing strategies
- Permission management
- Group collaboration
- Audit and compliance features

### Week 3: Administration and Security
**Target Audience**: Administrators and security team
**Duration**: 2 hours
**Format**: Technical workshop

#### System Administration
- User management and roles
- System configuration
- Monitoring and maintenance
- Backup and recovery procedures

#### Security Best Practices
- Authentication and authorization
- Security policies and compliance
- Incident response procedures
- Regular security assessments

### Week 4: Integration and Automation
**Target Audience**: Developers and DevOps
**Duration**: 1.5 hours
**Format**: Technical workshop

#### API Integration
- REST API usage and authentication
- CLI tool integration
- Automation scripts and workflows
- CI/CD pipeline integration

#### Best Practices
- Development workflows
- Production deployment
- Monitoring and alerting
- Performance optimization

## Training Materials

### Self-Paced Learning Resources
- **User Guide**: Complete step-by-step documentation
- **Video Tutorials**: Screen recordings of key workflows
- **Practice Environment**: Sandbox for hands-on learning
- **FAQ Document**: Common questions and answers

### Interactive Training
- **Live Demonstrations**: Real-time feature walkthroughs
- **Hands-on Exercises**: Guided practice sessions
- **Group Discussions**: Best practices sharing
- **Office Hours**: Regular Q&A sessions

### Assessment and Certification
- **Knowledge Checks**: Quick quizzes after each session
- **Practical Exercises**: Real-world scenario practice
- **Certification Test**: Comprehensive assessment
- **Ongoing Support**: Continued learning resources

## Training Delivery Methods

### In-Person Training
- **Location**: Conference room or training facility
- **Equipment**: Projector, laptops, network access
- **Materials**: Printed guides, exercise worksheets
- **Support**: Technical assistance during sessions

### Virtual Training
- **Platform**: Video conferencing with screen sharing
- **Recording**: Sessions recorded for later review
- **Interactive**: Chat, polls, and breakout rooms
- **Follow-up**: Email summaries and resources

### Hybrid Approach
- **Flexibility**: Mix of in-person and virtual sessions
- **Accessibility**: Accommodate different schedules
- **Recording**: All sessions available on-demand
- **Support**: Multiple channels for assistance

## Success Metrics

### Training Effectiveness
- **Attendance Rate**: Target 95% participation
- **Completion Rate**: Target 90% completion
- **Assessment Scores**: Target 80% pass rate
- **Feedback Scores**: Target 4.5/5 satisfaction

### Adoption Metrics
- **Active Users**: Track daily/weekly active users
- **Feature Usage**: Monitor feature adoption rates
- **Support Tickets**: Measure training effectiveness
- **User Feedback**: Collect ongoing feedback

### Business Impact
- **Security Improvements**: Reduced security incidents
- **Productivity Gains**: Faster secret management
- **Compliance**: Better audit and compliance scores
- **Cost Savings**: Reduced manual processes
EOF

# Create user onboarding checklist
cat > rollout/training/user-onboarding-checklist.md << 'EOF'
# User Onboarding Checklist

## Pre-Onboarding (IT/Admin Tasks)
- [ ] Create user account in Keyorix
- [ ] Assign appropriate role and permissions
- [ ] Add user to relevant groups/teams
- [ ] Send welcome email with login instructions
- [ ] Schedule onboarding session

## Day 1: Getting Started
- [ ] **Welcome Session** (30 minutes)
  - [ ] Introduction to Keyorix and team
  - [ ] Overview of security policies
  - [ ] Account setup and first login
  - [ ] Basic navigation walkthrough

- [ ] **First Secret Creation** (15 minutes)
  - [ ] Create first secret
  - [ ] Add metadata and tags
  - [ ] Understand security features
  - [ ] Save and verify secret

- [ ] **Initial Setup** (15 minutes)
  - [ ] Complete profile information
  - [ ] Set up two-factor authentication
  - [ ] Configure notification preferences
  - [ ] Review security settings

## Week 1: Core Features
- [ ] **Secret Management** (Day 2-3)
  - [ ] Create different types of secrets
  - [ ] Organize with tags and namespaces
  - [ ] Practice search and filtering
  - [ ] Update and delete secrets

- [ ] **Sharing Basics** (Day 4-5)
  - [ ] Share secret with colleague
  - [ ] Understand permission levels
  - [ ] Accept shared secrets
  - [ ] Review sharing history

## Week 2: Advanced Features
- [ ] **Collaboration** (Day 8-10)
  - [ ] Work with team groups
  - [ ] Manage group permissions
  - [ ] Use bulk operations
  - [ ] Practice version control

- [ ] **Integration** (Day 11-12)
  - [ ] Try CLI tool (if applicable)
  - [ ] Explore API documentation
  - [ ] Set up development workflow
  - [ ] Test automation scripts

## Week 3: Best Practices
- [ ] **Security Training** (Day 15-17)
  - [ ] Review security policies
  - [ ] Practice incident response
  - [ ] Understand compliance requirements
  - [ ] Complete security assessment

- [ ] **Optimization** (Day 18-19)
  - [ ] Optimize secret organization
  - [ ] Set up monitoring alerts
  - [ ] Review usage analytics
  - [ ] Identify improvement opportunities

## Week 4: Mastery and Assessment
- [ ] **Advanced Scenarios** (Day 22-24)
  - [ ] Handle complex sharing scenarios
  - [ ] Troubleshoot common issues
  - [ ] Mentor new team members
  - [ ] Contribute to best practices

- [ ] **Final Assessment** (Day 25)
  - [ ] Complete knowledge assessment
  - [ ] Demonstrate practical skills
  - [ ] Provide feedback on training
  - [ ] Receive certification

## Ongoing Support
- [ ] **Regular Check-ins**
  - [ ] 30-day follow-up meeting
  - [ ] 90-day progress review
  - [ ] Quarterly skill assessment
  - [ ] Annual training refresh

- [ ] **Continuous Learning**
  - [ ] Subscribe to update notifications
  - [ ] Join user community forums
  - [ ] Attend advanced training sessions
  - [ ] Share knowledge with team

## Resources and Support
- [ ] **Documentation Access**
  - [ ] User guide bookmarked
  - [ ] API documentation available
  - [ ] Troubleshooting guide accessible
  - [ ] FAQ document reviewed

- [ ] **Support Channels**
  - [ ] Help desk contact information
  - [ ] Team Slack/chat channels
  - [ ] Office hours schedule
  - [ ] Emergency contact procedures

## Success Criteria
- [ ] Can create and manage secrets independently
- [ ] Understands security best practices
- [ ] Can collaborate effectively with team
- [ ] Knows how to get help when needed
- [ ] Provides positive feedback on experience

---

**Onboarding Completion Date**: ___________
**Trainer Signature**: ___________
**User Signature**: ___________
EOF

# Create feedback collection system
log_info "Setting up feedback collection..."
cat > rollout/feedback/feedback-form.md << 'EOF'
# Keyorix Rollout Feedback Form

## User Information
- **Name**: ___________
- **Role**: ___________
- **Department**: ___________
- **Date**: ___________

## Training Experience (1-5 scale, 5 = Excellent)

### Training Quality
- **Content Clarity**: [ ] 1 [ ] 2 [ ] 3 [ ] 4 [ ] 5
- **Instructor Knowledge**: [ ] 1 [ ] 2 [ ] 3 [ ] 4 [ ] 5
- **Training Materials**: [ ] 1 [ ] 2 [ ] 3 [ ] 4 [ ] 5
- **Hands-on Practice**: [ ] 1 [ ] 2 [ ] 3 [ ] 4 [ ] 5

### Training Format
- **Session Length**: [ ] Too Short [ ] Just Right [ ] Too Long
- **Pace**: [ ] Too Fast [ ] Just Right [ ] Too Slow
- **Format Preference**: [ ] In-Person [ ] Virtual [ ] Hybrid [ ] Self-Paced

## System Usability (1-5 scale, 5 = Very Easy)

### Web Interface
- **Navigation**: [ ] 1 [ ] 2 [ ] 3 [ ] 4 [ ] 5
- **Secret Creation**: [ ] 1 [ ] 2 [ ] 3 [ ] 4 [ ] 5
- **Sharing Features**: [ ] 1 [ ] 2 [ ] 3 [ ] 4 [ ] 5
- **Search/Filter**: [ ] 1 [ ] 2 [ ] 3 [ ] 4 [ ] 5

### Features
- **Most Useful Feature**: ___________
- **Least Useful Feature**: ___________
- **Missing Features**: ___________

## Overall Satisfaction (1-5 scale, 5 = Very Satisfied)
- **Overall Experience**: [ ] 1 [ ] 2 [ ] 3 [ ] 4 [ ] 5
- **Would Recommend**: [ ] Yes [ ] No [ ] Maybe
- **Confidence Level**: [ ] 1 [ ] 2 [ ] 3 [ ] 4 [ ] 5

## Open Feedback

### What worked well?
___________

### What could be improved?
___________

### Additional training needed?
___________

### Suggestions for future enhancements?
___________

## Support and Documentation

### Documentation Quality (1-5 scale)
- **User Guide**: [ ] 1 [ ] 2 [ ] 3 [ ] 4 [ ] 5
- **API Documentation**: [ ] 1 [ ] 2 [ ] 3 [ ] 4 [ ] 5
- **Troubleshooting Guide**: [ ] 1 [ ] 2 [ ] 3 [ ] 4 [ ] 5

### Support Experience
- **Response Time**: [ ] Excellent [ ] Good [ ] Fair [ ] Poor
- **Solution Quality**: [ ] Excellent [ ] Good [ ] Fair [ ] Poor
- **Support Channels**: [ ] Sufficient [ ] Need More Options

## Future Needs
- **Advanced Training Interest**: [ ] Yes [ ] No
- **Integration Requirements**: ___________
- **Team-Specific Needs**: ___________

---

**Thank you for your feedback!**
Please return this form to: [feedback@company.com]
EOF

# Create rollout announcement templates
log_info "Creating rollout announcements..."
cat > rollout/announcements/rollout-announcement.md << 'EOF'
# 🚀 Introducing Keyorix: Our New Secret Management System

## What is Keyorix?

We're excited to announce the rollout of **Keyorix**, our new enterprise-grade secret management system! Keyorix provides a secure, user-friendly platform for storing, sharing, and managing sensitive information across our organization.

## Why Keyorix?

### 🔒 Enhanced Security
- Military-grade encryption (AES-256-GCM)
- Multi-factor authentication
- Role-based access control
- Comprehensive audit logging

### 🤝 Better Collaboration
- Secure secret sharing with team members
- Group-based permissions
- Real-time collaboration features
- Activity tracking and notifications

### 📊 Improved Productivity
- Intuitive web interface
- Powerful CLI tools
- API integration capabilities
- Advanced search and organization

### 📋 Compliance Ready
- GDPR, SOC 2, and HIPAA compliance
- Detailed audit trails
- Automated compliance reporting
- Regular security assessments

## Rollout Timeline

### Phase 1: Pilot Group (Week 1-2)
- **Participants**: IT team and security champions
- **Focus**: System validation and feedback collection
- **Training**: Intensive hands-on sessions

### Phase 2: Early Adopters (Week 3-4)
- **Participants**: Development and DevOps teams
- **Focus**: Integration and workflow optimization
- **Training**: Technical workshops and API training

### Phase 3: Department Rollout (Week 5-8)
- **Participants**: All departments (staged rollout)
- **Focus**: User adoption and change management
- **Training**: Department-specific training sessions

### Phase 4: Organization-wide (Week 9-10)
- **Participants**: All remaining users
- **Focus**: Complete migration and optimization
- **Training**: Self-paced learning and support

## What to Expect

### Training and Support
- **Comprehensive Training**: Multi-format training program
- **Documentation**: Complete user guides and tutorials
- **Support**: Dedicated help desk and office hours
- **Community**: Internal user forums and knowledge sharing

### Migration Process
- **Gradual Transition**: Phased migration from existing systems
- **Data Import**: Automated migration of existing secrets
- **Parallel Operation**: Old and new systems running simultaneously
- **Validation**: Thorough testing and verification

### Key Features Available
- **Web Dashboard**: Modern, intuitive interface
- **Mobile Access**: Responsive design for all devices
- **CLI Tools**: Command-line interface for developers
- **API Access**: RESTful API for integrations
- **Monitoring**: Real-time system health and usage analytics

## Getting Started

### For Pilot Group Members
1. **Check Your Email**: Look for your account setup instructions
2. **Attend Training**: Mandatory training session scheduled
3. **Provide Feedback**: Your input is crucial for success
4. **Champion the Change**: Help others understand the benefits

### For Everyone Else
1. **Stay Informed**: Watch for updates and announcements
2. **Prepare for Training**: Training schedules will be shared soon
3. **Ask Questions**: Reach out to the project team
4. **Be Patient**: Rollout will be gradual and well-supported

## Support and Resources

### Getting Help
- **Help Desk**: help@company.com
- **Training Team**: training@company.com
- **Project Manager**: [Project Manager Name]
- **Emergency Support**: Available 24/7

### Resources
- **Project Website**: [Internal URL]
- **Training Materials**: [Training Portal URL]
- **Documentation**: [Docs URL]
- **FAQ**: [FAQ URL]

## Benefits for You

### Personal Benefits
- **Secure Storage**: Never worry about password security again
- **Easy Access**: Access your secrets from anywhere, anytime
- **Better Organization**: Keep all your secrets organized and searchable
- **Peace of Mind**: Know your sensitive data is protected

### Team Benefits
- **Improved Collaboration**: Share secrets securely with team members
- **Better Workflows**: Integrate with existing development processes
- **Reduced Risk**: Eliminate insecure sharing methods
- **Compliance**: Meet regulatory requirements automatically

## Questions and Concerns

### Common Questions
- **Q: Will my existing passwords be migrated?**
  A: Yes, we have automated migration tools for most systems.

- **Q: How long will the training take?**
  A: Initial training is 2 hours, with ongoing support available.

- **Q: What if I have technical issues?**
  A: Our support team is ready to help with any technical challenges.

- **Q: Is this mandatory?**
  A: Yes, this is part of our security improvement initiative.

### Feedback Welcome
We want to hear from you! Please share your thoughts, concerns, and suggestions:
- **Email**: feedback@company.com
- **Slack**: #keyorix-rollout
- **Office Hours**: Fridays 2-4 PM

## Thank You

Thank you for your patience and cooperation during this important security upgrade. Together, we're making our organization more secure and efficient.

**The Keyorix Project Team**

---

*This announcement will be followed by detailed training schedules and technical documentation.*
EOF

# Create rollout success metrics
log_info "Setting up success metrics tracking..."
cat > rollout/rollout-metrics.md << 'EOF'
# Rollout Success Metrics

## User Adoption Metrics

### Registration and Activation
- **Target**: 95% of users registered within 2 weeks of their phase
- **Measurement**: User account creation and first login
- **Current**: 0% (baseline)

### Training Completion
- **Target**: 90% training completion rate
- **Measurement**: Training session attendance and assessment scores
- **Current**: 0% (baseline)

### Active Usage
- **Target**: 80% weekly active users within 1 month
- **Measurement**: Users who log in and perform actions weekly
- **Current**: 0% (baseline)

## Feature Adoption Metrics

### Core Features
- **Secret Creation**: Target 100% of users create at least 1 secret
- **Secret Sharing**: Target 60% of users share at least 1 secret
- **Web Dashboard**: Target 95% primary interface usage
- **Mobile Access**: Target 40% mobile usage

### Advanced Features
- **CLI Usage**: Target 30% of technical users
- **API Integration**: Target 20% of development teams
- **Bulk Operations**: Target 25% of power users
- **Advanced Search**: Target 50% of regular users

## System Performance Metrics

### Availability and Reliability
- **Uptime**: Target 99.9% availability
- **Response Time**: Target <200ms average response time
- **Error Rate**: Target <0.1% error rate
- **Support Tickets**: Target <5% of users requiring support

### Security Metrics
- **Security Incidents**: Target 0 security breaches
- **Compliance Score**: Target 100% compliance checklist
- **Audit Findings**: Target 0 critical audit findings
- **Password Reuse**: Target 90% reduction in password reuse

## Business Impact Metrics

### Productivity Improvements
- **Time Savings**: Target 30% reduction in secret management time
- **Process Efficiency**: Target 50% faster secret sharing
- **Reduced Errors**: Target 80% reduction in security-related errors
- **Support Reduction**: Target 60% reduction in password-related support

### Security Improvements
- **Incident Reduction**: Target 90% reduction in security incidents
- **Compliance Score**: Target improvement from 70% to 95%
- **Audit Readiness**: Target 100% audit readiness
- **Risk Reduction**: Target 80% reduction in security risk score

## User Satisfaction Metrics

### Training Satisfaction
- **Training Quality**: Target 4.5/5 average rating
- **Content Relevance**: Target 4.5/5 average rating
- **Instructor Effectiveness**: Target 4.5/5 average rating
- **Material Quality**: Target 4.5/5 average rating

### System Satisfaction
- **Ease of Use**: Target 4.0/5 average rating
- **Feature Completeness**: Target 4.0/5 average rating
- **Performance**: Target 4.5/5 average rating
- **Overall Satisfaction**: Target 4.2/5 average rating

### Support Satisfaction
- **Response Time**: Target 4.5/5 average rating
- **Solution Quality**: Target 4.5/5 average rating
- **Support Accessibility**: Target 4.5/5 average rating
- **Documentation Quality**: Target 4.0/5 average rating

## Rollout Phase Metrics

### Phase 1: Pilot Group (Weeks 1-2)
- **Participants**: 20 users (IT and security team)
- **Success Criteria**: 
  - 100% training completion
  - 95% daily active usage
  - <5 critical issues identified
  - 4.0/5 satisfaction score

### Phase 2: Early Adopters (Weeks 3-4)
- **Participants**: 100 users (development teams)
- **Success Criteria**:
  - 95% training completion
  - 85% weekly active usage
  - <10 integration issues
  - 4.0/5 satisfaction score

### Phase 3: Department Rollout (Weeks 5-8)
- **Participants**: 500 users (all departments)
- **Success Criteria**:
  - 90% training completion
  - 80% weekly active usage
  - <20 support tickets per week
  - 4.0/5 satisfaction score

### Phase 4: Organization-wide (Weeks 9-10)
- **Participants**: 1000+ users (entire organization)
- **Success Criteria**:
  - 85% training completion
  - 75% weekly active usage
  - <50 support tickets per week
  - 3.8/5 satisfaction score

## Measurement and Reporting

### Data Collection
- **Automated Metrics**: System logs and analytics
- **User Surveys**: Monthly satisfaction surveys
- **Training Assessments**: Post-training evaluations
- **Support Metrics**: Help desk ticket analysis

### Reporting Schedule
- **Daily**: System performance and availability
- **Weekly**: User adoption and activity metrics
- **Monthly**: Comprehensive rollout progress report
- **Quarterly**: Business impact and ROI analysis

### Success Criteria
- **Overall Success**: 80% of all metrics meet targets
- **Critical Success**: 100% of security and availability metrics
- **User Success**: 75% user satisfaction across all categories
- **Business Success**: Measurable productivity and security improvements

## Risk Mitigation

### Identified Risks
- **Low Adoption**: Comprehensive training and change management
- **Technical Issues**: Extensive testing and support resources
- **User Resistance**: Clear communication and benefits demonstration
- **Security Concerns**: Transparent security documentation

### Mitigation Strategies
- **Phased Rollout**: Gradual deployment with feedback incorporation
- **Extensive Support**: Multiple support channels and resources
- **Continuous Improvement**: Regular feedback collection and system updates
- **Executive Sponsorship**: Leadership support and communication
EOF

log_success "Team rollout preparation completed!"

cat << 'EOF'

🚀 Team Rollout Summary
======================

✅ Staging environment configuration created
✅ Comprehensive training plan developed
✅ User onboarding checklist prepared
✅ Feedback collection system established
✅ Rollout announcements drafted
✅ Success metrics framework defined

📁 Rollout Files Created:
├── rollout/staging/docker-compose.staging.yml
├── rollout/staging/nginx-staging.conf
├── rollout/training/team-training-plan.md
├── rollout/training/user-onboarding-checklist.md
├── rollout/feedback/feedback-form.md
├── rollout/announcements/rollout-announcement.md
└── rollout/rollout-metrics.md

🎯 Next Steps:
1. Deploy staging environment for testing
2. Schedule pilot group training sessions
3. Customize announcements for your organization
4. Set up feedback collection mechanisms
5. Begin phased rollout execution

📊 Success Metrics:
- 95% user registration within phase timeline
- 90% training completion rate
- 80% weekly active users within 1 month
- 4.0/5 average satisfaction score

EOF

log_success "Task 9: Team Rollout - COMPLETED!"