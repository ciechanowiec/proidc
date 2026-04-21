FROM eclipse-temurin:25-jdk

WORKDIR /app
COPY apt-installer.sh .
RUN ./apt-installer.sh
RUN rm apt-installer.sh

COPY target/proidc-1.6.0.jar /app
# exec is required in order to set the Java process as PID 1 inside the container, since Docker sends
# termination signals only to PID 1, and we need those signals to be handled by the java process:
RUN printf '#!/bin/bash\n\nexec java -jar proidc-1.6.0.jar\n\ntail -f /dev/null\n' > starter.sh
RUN chmod 755 starter.sh

VOLUME /var/logs/proidc
