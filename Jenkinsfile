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

    DD_URL             = 'http://localhost:8280'
    DD_PRODUCT_TYPE    = 'DevSecOps'
    DD_PRODUCT_NAME    = 'DevSecOps-Product'
    ENGAGEMENT_NAME    = 'App Build'
    DD_CREDENTIALS_ID  = 'DD_API_KEY'
  }

  stages {

    stage('Checkout') {
      steps {
        sh """
          rm -rf ${PROJECT_DIR}
          git clone --depth=1 ${REPO_URL} ${PROJECT_DIR}
          mkdir -p ${REPORT_DIR} flags
          # simpan metadata git utk Dojo
          cd ${PROJECT_DIR}
          git rev-parse HEAD > ../commit.txt || echo unknown > ../commit.txt
          git rev-parse --abbrev-ref HEAD > ../branch.txt || echo main > ../branch.txt
        """
      }
    }

    stage('Security Scans') {
      parallel {
        stage('SAST - Bandit & Semgrep') {
          steps {
            sh """
              cd \${PROJECT_DIR}
              bandit -r . -f json -o ../\${BANDIT_REPORT} || true
              semgrep --config=auto --json -o ../\${SEMGREP_REPORT} . || true
            """
          }
        }

        stage('SCA - Anchore Grype') {
          steps {
            sh """
              cd \${PROJECT_DIR}
              grype dir:. -o json > ../\${GRYPE_FS_REPORT} || true
            """
          }
        }

        stage('Secrets Scan - TruffleHog') {
          steps {
            sh """
              if [ -d "\${PROJECT_DIR}/.git" ]; then
                sudo trufflehog git --json \${PROJECT_DIR} > \${TRUFFLEHOG_REPORT} || true
              else
                sudo trufflehog filesystem --directory \${PROJECT_DIR} --json > \${TRUFFLEHOG_REPORT} || true
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
            grep -iqE '\\"issue_severity\\":\\s*\\"HIGH\\"|\\"CRITICAL\\"' \${BANDIT_REPORT} && touch flags/sast_high || true
            grep -iqE '\\"severity\\":\\s*\\"ERROR\\"|\\"HIGH\\"|\\"CRITICAL\\"' \${SEMGREP_REPORT} && touch flags/sast_high || true
            grep -iqE '\\"severity\\":\\s*\\"High\\"|\\"severity\\":\\s*\\"Critical\\"' \${GRYPE_FS_REPORT} && touch flags/grype_high || true
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
          trivy image --format json --output \${TRIVY_IMAGE_REPORT} --ignore-unfixed --scanners vuln,secret \${DOCKER_IMAGE} || true
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

    // ======== NEW: Publish all reports to DefectDojo ========
    stage('Publish to DefectDojo') {
      steps {
        script {
          // collect git metadata prepared at Checkout
          def COMMIT_HASH = readFile('commit.txt').trim()
          def branch_name = readFile('branch.txt').trim()
          def SOURCE_CODE_URL = env.REPO_URL

          // daftar file ↔ scanType sesuai DefectDojo
          def uploads = [
            [file: "${BANDIT_REPORT}",      scanType: 'Bandit Scan'],
            [file: "${SEMGREP_REPORT}",     scanType: 'Semgrep JSON Report'],
            [file: "${GRYPE_FS_REPORT}",    scanType: 'Anchore Grype'],
            [file: "${TRUFFLEHOG_REPORT}",  scanType: 'Trufflehog Scan'],
            [file: "${TRIVY_IMAGE_REPORT}", scanType: 'Trivy Scan'],
            [file: "${NUCLEI_REPORT}",      scanType: 'Nuclei Scan']
          ]

          // kebijakan verified per scan
          def verifiedPolicy = [
            'Bandit Scan'          : false,
            'Semgrep JSON Report'  : false,
            'Anchore Grype'        : false,
            'Trufflehog Scan'      : true,
            'Trivy Scan'           : false,
            'Nuclei Scan'          : false
          ]

          withCredentials([string(credentialsId: env.DD_CREDENTIALS_ID, variable: 'DD_API_KEY')]) {

            // Cek apakah engagement sudah ada (by product+name)
            def engagementCount = sh(
              script: """
                curl -s -G "\${DD_URL}/api/v2/engagements/" \
                  -H "Authorization: Token \${DD_API_KEY}" \
                  --data-urlencode "name=${ENGAGEMENT_NAME}" \
                  --data-urlencode "product__name=${DD_PRODUCT_NAME}" | jq -r '.count'
              """,
              returnStdout: true
            ).trim()

            def dateFields = ''
            if (engagementCount == '0') {
              def startDate = java.time.LocalDate.now().toString()
              def endDate   = java.time.LocalDate.now().plusDays(180).toString()
              dateFields = "-F engagement_start_date=${startDate} -F engagement_end_date=${endDate}"
              echo "🆕 First-time engagement '${env.ENGAGEMENT_NAME}' → set dates ${startDate}..${endDate}"
            } else {
              echo "↔️ Engagement '${env.ENGAGEMENT_NAME}' already exists → skip date fields."
            }

            uploads.each { u ->
              if (fileExists(u.file) && sh(script: "test -s ${u.file}", returnStatus: true) == 0) {
                def verifiedFlag = verifiedPolicy.get(u.scanType, false) ? 'true' : 'false'
                echo "📤 Reimport ${u.file} → DefectDojo (${u.scanType})"
                sh """
                  curl -sS -X POST "\${DD_URL}/api/v2/reimport-scan/" \
                    -H "Authorization: Token \${DD_API_KEY}" \
                    -F "product_name=${DD_PRODUCT_NAME}" \
                    -F "product_type_name=${DD_PRODUCT_TYPE}" \
                    -F "engagement_name=${ENGAGEMENT_NAME}" \
                    -F "scan_type=${u.scanType}" \
                    -F "file=@${u.file}" \
                    -F "build_id=${BUILD_NUMBER}" \
                    -F "commit_hash=${COMMIT_HASH}" \
                    -F "branch_tag=${branch_name}" \
                    -F "source_code_management_uri=${SOURCE_CODE_URL}" \
                    -F "version=build-${BUILD_NUMBER}" \
                    -F "active=true" \
                    -F "verified=${verifiedFlag}" \
                    -F "do_not_reactivate=false" \
                    -F "close_old_findings=true" \
                    -F "auto_create_context=true" \
                    ${dateFields}
                """
              } else {
                echo "⏭️ Skip upload: ${u.file} tidak ada atau kosong."
              }
            }
          }
        }
      }
    }
    // =========================================================

    stage('Security Approval (Manual Gate)') {
      when {
        expression {
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
