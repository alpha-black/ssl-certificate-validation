pipeline {
    agent { docker 'python:3.5.1' }
    stages {
        stage('build') {
            steps {
                sh 'gcc -o validate ssl_cert_verification.c -lcrypto -lssl -g'
            }
        }
    }
}