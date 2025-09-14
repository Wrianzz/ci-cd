pipeline {
  agent any

  environment {
    REPO_URL           = "https://github.com/Wrianzz/ci-cd.git" 
    PROJECT_DIR        = "ci-cd"
    REPORT_DIR         = "reports"
    BANDIT_REPORT      = "reports/bandit-report.json"
    SEMGREP_REPORT     = "reports/semgrep-report.json"
    GRYPE_FS_REPORT    = "reports/grype-fs.json"
    TRUFFLEHOG_REPORT  = "reports/trufflehog-report.json"
    TRIVY_IMAGE_REPORT = "reports/trivy-image-report.json"
    NUCLEI_REPORT      = "reports/nuclei-report.json"
    FINAL_REPORT       = "reports/final-security-report.txt"
    DISCORD_WEBHOOK    = credentials('discord-webhook-url')
    DOCKER_IMAGE       = "flask-vuln-app"
    CONTAINER_NAME     = "vulnapp"
  }

  stages {

    stage('Checkout') {
      steps {
        sh """
          rm -rf ${PROJECT_DIR}
          git clone --depth=1 ${REPO_URL} ${PROJECT_DIR}
          mkdir -p ${REPORT_DIR} flags
          """
      }
    }

    stage('Security Scans') {
      parallel {
        stage('SAST - Bandit & Semgrep') {
          steps {
            sh """
              cd \${PROJECT_DIR}
              # Bandit untuk semua file Python di repo
              bandit -r . -f json -o ../\${BANDIT_REPORT} || true
              # Semgrep auto config ke seluruh repo
              semgrep --config=auto --json -o ../\${SEMGREP_REPORT} . || true
            """
          }
        }

        stage('SCA - Anchore Grype') {
          steps {
            sh """
              cd \${PROJECT_DIR}
              # Scan seluruh filesystem project
              grype dir:. -o json > ../\${GRYPE_FS_REPORT} || true
            """
          }
        }

        stage('Secrets Scan - TruffleHog') {
          steps {
            sh """
              # Scan sejarah git (jika ada .git) dan filesystem
              if [ -d "\${PROJECT_DIR}/.git" ]; then
                trufflehog git --json \${PROJECT_DIR} > \${TRUFFLEHOG_REPORT} || true
              else
                trufflehog filesystem --directory \${PROJECT_DIR} --json > \${TRUFFLEHOG_REPORT} || true
              fi
            """
          }
        }
      }
    }

    stage('Evaluate Static Scans') {
      steps {
        script {
          sh """
            mkdir -p flags

            # Bandit & Semgrep: tandai jika ada HIGH/CRITICAL
            grep -iqE '\\"issue_severity\\":\\s*\\"HIGH\\"|\\"CRITICAL\\"' \${BANDIT_REPORT} && touch flags/sast_high || true
            grep -iqE '\\"severity\\":\\s*\\"ERROR\\"|\\"HIGH\\"|\\"CRITICAL\\"' \${SEMGREP_REPORT} && touch flags/sast_high || true

            # Grype FS: High/Critical
            grep -iqE '\\"severity\\":\\s*\\"High\\"|\\"severity\\":\\s*\\"Critical\\"' \${GRYPE_FS_REPORT} && touch flags/grype_high || true

            # TruffleHog: adanya temuan rahasia dianggap perlu atensi
            [ -s \${TRUFFLEHOG_REPORT} ] && touch flags/secrets_found || true
          """
        }
      }
    }

    stage('Build Docker Image') {
      steps {
        sh """
          cd \${PROJECT_DIR}
          docker build -t \${DOCKER_IMAGE} .
        """
      }
    }
    
    stage('Trivy Image Scan') {
      steps {
        sh """
          # Scan image, simpan semua temuan (vuln & secret) sebagai JSON
          trivy image --format json --output \${TRIVY_IMAGE_REPORT} --ignore-unfixed --scanners vuln,secret \${DOCKER_IMAGE} || true

          # Tandai jika ada HIGH/CRITICAL
          grep -iqE '\\"Severity\\":\\s*\\"HIGH\\"|\\"Severity\\":\\s*\\"CRITICAL\\"' \${TRIVY_IMAGE_REPORT} && touch flags/trivy_high || true
        """
      }
    }
    
    stage('Deploy') {
      steps {
        sh """
          docker rm -f \${CONTAINER_NAME} || true
          docker run -d -p 5000:5000 --name \${CONTAINER_NAME} \${DOCKER_IMAGE}
          sleep 5
        """
      }
    }

    stage('DAST - Nuclei') {
      steps {
        sh """
          nuclei -u http://localhost:5000 -j -o \${NUCLEI_REPORT} || true
        """
      }
    }

    stage('Evaluate DAST') {
      steps {
        script {
          def hasHigh = sh(script: "grep -i '\\\"severity\\\":\\\"high\\\"\\|\\\"severity\\\":\\\"critical\\\"' \${NUCLEI_REPORT}", returnStatus: true) == 0

          sh 'python3 scripts/generate_report.py || true'

          if (hasHigh) {
            sh 'touch flags/nuclei_high'
            sendDiscord("❌ **DAST finding**: Ada High/Critical di Nuclei. Container akan dihentikan.")
            sh "docker rm -f \${CONTAINER_NAME} || true"
            sh "curl -F \"file=@\${FINAL_REPORT}\" \${DISCORD_WEBHOOK}"
          }
        }
      }
    }

    stage('Notify Developer') {
      steps {
        script {
          def anyFlags = sh(script: "ls flags/* 2>/dev/null | wc -l", returnStdout: true).trim() != "0"
          if (anyFlags) {
            sendDiscord("⚠️ **Findings detected**: Ada temuan High/Critical atau secrets. Menunggu **Approval** di stage terakhir. Laporan terlampir.")
          } else {
            sendDiscord("✅ **Pipeline passed**: Tidak ditemukan High/Critical. Laporan akhir terlampir.")
          }
          sh "curl -F \"file=@\${FINAL_REPORT}\" \${DISCORD_WEBHOOK} || true"
        }
      }
    }

    stage('Security Approval (Manual Gate)') {
      when {
        expression {
          // Muncul hanya jika ada temuan yang butuh keputusan
          return fileExists('flags/sast_high') ||
                 fileExists('flags/grype_high') ||
                 fileExists('flags/trivy_high') ||
                 fileExists('flags/nuclei_high') ||
                 fileExists('flags/secrets_found')
        }
      }
      steps {
        script {
          def decision = input(
            id: 'SecurityApproval',
            message: 'Ditemukan High/Critical issues atau secrets. Lanjutkan release?',
            parameters: [
              choice(name: 'APPROVAL', choices: ['Stop', 'Proceed'], description: 'Pilih tindakan')
            ]
          )
          if (decision == 'Stop') {
            error("Pipeline dihentikan oleh reviewer karena temuan High/Critical.")
          } else {
            sendDiscord("🔏 **Approved**: Lanjut meskipun ada temuan. Pastikan tiket perbaikan dibuat.")
          }
        }
      }
    }
  }

  post {
    always {
      // Simpan SEMUA artifact scanner
      archiveArtifacts artifacts: 'reports/**', fingerprint: true
    }
  }
}

def sendDiscord(String message) {
  sh """
    curl -X POST -H 'Content-Type: application/json' \
    -d '{"content": "${message}"}' ${DISCORD_WEBHOOK}
  """
}
