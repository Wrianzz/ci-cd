pipeline {
    agent any

    parameters {
        string(name: 'SCAN_FILE', defaultValue: 'app.py', description: 'File to scan using Nuclei')
    }

    environment {
        NUCLEI_REPORT = 'nuclei-report.json'
    }

    stages {
        stage('Checkout Code') {
            steps {
                git 'https://github.com/Wrianzz/cicd.git'
            }
        }

        stage('Install Dependencies') {
            steps {
                sh '''
                    python3 -m pip install --upgrade pip
                    pip install -r requirements.txt
                '''
            }
        }

        stage('Install Nuclei') {
            steps {
                sh '''
                    curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
                    | grep "browser_download_url.*linux_amd64.zip" \
                    | cut -d : -f 2,3 \
                    | tr -d \\" \
                    | wget -i -
                    
                    unzip nuclei*.zip
                    sudo mv nuclei /usr/local/bin/
                '''
            }
        }

        stage('Run Nuclei Scan') {
            steps {
                sh '''
                    nuclei -target ${SCAN_FILE} -file -type file -j -o ${NUCLEI_REPORT}
                '''
            }
        }

        stage('Evaluate Scan Results') {
            steps {
                script {
                    def hasHigh = sh(script: "grep -i '\"severity\":\"high\"\\|\"severity\":\"critical\"' ${NUCLEI_REPORT}", returnStatus: true) == 0
                    def hasOther = sh(script: "grep -i '\"severity\":\"medium\"\\|\"severity\":\"low\"\\|\"severity\":\"info\"' ${NUCLEI_REPORT}", returnStatus: true) == 0

                    if (hasHigh) {
                        echo 'Aborted : High or Critical vulnerabilities found!'
                        sh "cat ${NUCLEI_REPORT}"
                        error("Build failed due to High/Critical findings.")
                    } else if (hasOther) {
                        echo 'Warning : Medium or Low vulnerabilities found. Build will continue with warning.'
                        sh "cat ${NUCLEI_REPORT}"
                    } else {
                        echo 'No vulnerabilities found.'
                    }
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                sh '''
                    docker build -t flask-vuln-app .
                '''
            }
        }

        stage('Run Docker Container') {
            steps {
                sh '''
                    docker run -d -p 5000:5000 --name vulnapp flask-vuln-app || true
                '''
            }
        }
    }
}
