# java libraries: version
BCPROV_t=jdk16
BCPROV_v=1.46
JAVA_PARSER=1.0.8
SQLJET=1.1.6
JUNIT=4.12
ANT=1.8.4


default: libdownload javabuild

libdownload:
	-mkdir -p lib
	wget -P lib -nc http://central.maven.org/maven2/org/bouncycastle/bcprov-${BCPROV_t}/${BCPROV_v}/bcprov-${BCPROV_t}-${BCPROV_v}.jar
	wget -P lib -nc http://central.maven.org/maven2/com/google/code/javaparser/javaparser/$(JAVA_PARSER)/javaparser-$(JAVA_PARSER).jar
	wget -P lib -nc http://central.maven.org/maven2/org/tmatesoft/sqljet/sqljet/$(SQLJET)/sqljet-$(SQLJET).jar
	wget -P lib -nc http://central.maven.org/maven2/junit/junit/$(JUNIT)/junit-$(JUNIT).jar
	wget -P lib -nc http://central.maven.org/maven2/org/apache/ant/ant/$(ANT)/ant-$(ANT).jar

javabuild: 
	-mkdir -p bin
	javac -sourcepath src \
          -classpath "lib/*" \
          -d bin \
          src/tests/*.java    

clean:
	-rm -r bin

