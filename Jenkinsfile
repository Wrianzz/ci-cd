pipeline {
  agent any

  parameters {
    string(name: 'SCAN_FILE', defaultValue: 'app.py', description: 'File for security scan')
  }

  environment {
    REPO_URL = "git@github.com:Wrianzz/ci-cd.git"
    PROJECT_DIR = "ci-cd"
    BANDIT_REPORT = "reports/bandit-report.json"
    SEMGREP_REPORT = "reports/semgrep-report.json"
    NUCLEI_REPORT = "reports/nuclei-report.json"
    FINAL_REPORT = "reports/final-security-report.txt"
    DISCORD_WEBHOOK = credentials('discord-webhook-url')
  }

  stages {

    stage('Checkout') {
      steps {
        sshagent (credentials: ['github-ssh-key']) {
          sh '''
            rm -rf ${PROJECT_DIR}
            git clone ${REPO_URL}
          '''
        }
      }
    }

    stage('SAST - Bandit & Semgrep') {
      steps {
        sh '''
          cd ${PROJECT_DIR}
          mkdir -p ../reports
          bandit -f json -o ../${BANDIT_REPORT} ${SCAN_FILE} || true
          semgrep --config=auto --json -o ../${SEMGREP_REPORT} ${SCAN_FILE} || true
        '''
      }
    }

    stage('Evaluate SAST') {
      steps {
        script {
          def highBandit = sh(script: "grep -iE '\"issue_severity\":\\s*\"HIGH\"|\"CRITICAL\"' ${BANDIT_REPORT}", returnStatus: true) == 0
          def highSemgrep = sh(script: "grep -iE '\"severity\":\\s*\"ERROR\"|\"HIGH\"|\"CRITICAL\"' ${SEMGREP_REPORT}", returnStatus: true) == 0

          sh 'python3 scripts/generate_report.py'

          sendDiscord("❌ *SAST failed*: High/Critical vulnerability ditemukan. Laporan terlampir.")
          sh "curl -F \"file=@${FINAL_REPORT}\" ${DISCORD_WEBHOOK}"

          if (highBandit || highSemgrep) {
            error("Stopping pipeline due to high/critical issues in SAST.")
          }
        }
      }
    }

    stage('Build Docker Image') {
      steps {
        sh '''
          cd ${PROJECT_DIR}
          docker build -t flask-vuln-app .
        '''
      }
    }

    stage('Deploy') {
      steps {
        sh '''
          docker rm -f vulnapp || true
          docker run -d -p 5000:5000 --name vulnapp flask-vuln-app
          sleep 5
        '''
      }
    }

    stage('DAST - Nuclei') {
      steps {
        sh '''
          mkdir -p reports
          nuclei -u http://localhost:5000 -j -o ${NUCLEI_REPORT} || true
        '''
      }
    }

    stage('Evaluate DAST') {
      steps {
        script {
          def hasHigh = sh(script: "grep -i '\"severity\":\"high\"\\|\"severity\":\"critical\"' ${NUCLEI_REPORT}", returnStatus: true) == 0

          sh 'python3 scripts/generate_report.py'

          if (hasHigh) {
            sendDiscord("❌ *DAST failed*: High/Critical ditemukan saat Nuclei scan.")
            sh "curl -F \"file=@${FINAL_REPORT}\" ${DISCORD_WEBHOOK}"
            error("Stopping pipeline due to high/critical issues in DAST.")
          }
        }
      }
    }

    stage('Notify Developer') {
      steps {
        script {
          sendDiscord("✅ *Pipeline passed*: Tidak ditemukan critical issue. Laporan akhir terlampir.")
          sh "curl -F \"file=@${FINAL_REPORT}\" ${DISCORD_WEBHOOK}"
        }
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'reports/*', fingerprint: true
    }
  }
}

def sendDiscord(String message) {
  sh """
    curl -X POST -H 'Content-Type: application/json' \
    -d '{"content": "${message}"}' ${DISCORD_WEBHOOK}
  """
}
