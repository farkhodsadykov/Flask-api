FROM centos:7
COPY . /app
RUN yum -y install epel-release
RUN yum -y install python-pip mariadb-devel gcc
RUN yum -y install python-devel libxslt-devel libffi-devel openssl-devel && yum clean all
WORKDIR /app
RUN pip install --upgrade pip
EXPOSE 5000
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
