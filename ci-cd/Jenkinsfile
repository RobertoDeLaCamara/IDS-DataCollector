pipeline {
    agent {
        label 'pytest'  // Agent label
    }
    stages {
        stage('Setup') {
            steps {
                sh 'pip install -r requirements.txt'
            }
        }
        stage('Run Tests') {
            steps {
                sh 'pytest services/data-collector-service/tests/ --disable-warnings --junitxml=reports/data-collector-service-report.xml'
            }
        }
    
    }
    post {
        always {
            junit '**/reports/*.xml'
        }
    }
}