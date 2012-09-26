package de.uni.trier.infsec.tools.envgen;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;

import de.uni.trier.infsec.tools.envgen.SystemInterface.ClassInterface;
import de.uni.trier.infsec.tools.envgen.SystemInterface.Constructor;
import de.uni.trier.infsec.tools.envgen.SystemInterface.Exception;
import de.uni.trier.infsec.tools.envgen.SystemInterface.Field;
import de.uni.trier.infsec.tools.envgen.SystemInterface.Method;
import de.uni.trier.infsec.tools.envgen.SystemInterface.Parameter;

public class SystemGenerator {

	private HashMap<String, ClassInterface> classMap = new HashMap<String, ClassInterface>();
	
	public String generate(SystemInterface si, String outputPath) throws IOException {
		StringBuffer staticMethods = new StringBuffer();
		
		int identifier = 10000; // Initial value for Identifier

		for (ClassInterface ci : si.classes) {
			// Add a new Constructor which does not take any parameters
			Constructor c = new Constructor(ci.name);
			c.visibility = "public";
			ci.constructors.add(c);
			
			
			for (Method m : ci.methods) {
				StringBuilder stringBuilder = new StringBuilder();
				
				stringBuilder.append(String.format("\t\tEnv.untrustedOutput(%d); // %s is method ID of %s \n", ++identifier, identifier, m.name));
				for (Parameter p : m.parameters) {
					if (p.type.equals("int")) {
						stringBuilder.append(String.format("\t\tEnv.untrustedOutput(%s); \n", p.name));
					} else if (p.type.equals("byte[]")) {
						stringBuilder.append(String.format("\t\tEnv.untrustedOutputMessage(%s);\n", p.name));
					}
				}
				
				switch (m.type) {
				case "void":
					stringBuilder.append("\t\treturn;\n");
					break;
				case "int":
					stringBuilder.append("\t\treturn Env.untrustedInput();\n");
					break;
				case "byte[]":
					stringBuilder.append("\t\treturn Env.untrustedInputMessage();\n");
					break;
				default:
					stringBuilder.append(String.format("\t\treturn Env.createObject_%s();\n", m.type.replaceAll("\\.", "_")));
					break;
				}
				
				for (Exception e : m.exceptions) {
					stringBuilder.append(String.format("\t\tif (Env.untrustedInput()==0) throw Env.createObject_%s();\n", e.name));					
				}
				m.body = stringBuilder.toString();
			}
			
			staticMethods.append(String.format("\tpublic static %s createObject_%s() {\n", ci.name, ci.name));
			staticMethods.append(String.format("\t\t%s result = new %s();\n", ci.name, ci.name));
			for (Field f : ci.fields) {
				switch (f.type) {
				case "int":
					staticMethods.append(String.format("\t\tresult.%s = Env.untrustedInput();\n", f.name));
					break;
				case "byte[]":
					staticMethods.append(String.format("\t\tresult.%s = Env.untrustedInputMessage();\n", f.name));
					break;
				}					
			}
			staticMethods.append("\t\treturn result;\n");
			staticMethods.append("\t}\n\n");
		}
		StringBuffer out = new StringBuffer();
		BufferedReader br = new BufferedReader(new InputStreamReader(this.getClass().getResourceAsStream("template.txt")));
		while (br.ready()) {
			out.append(br.readLine().replaceAll("%%%%%%TEMPLATE%%%%%%", staticMethods.toString()));
			out.append("\n");
		}

		// Handle Extends
		// TODO: Only extends in Ie allowed

		// First, we add all classes to a map to make access faster
		for (ClassInterface ci : si.classes) {			
			classMap.put(ci.name, ci);
		}
		// Now recursively add extended fields top-down
		for (ClassInterface ci : si.classes) {
			addExtendedFields(ci);
		}
		// Last Step: Write code to file
		if (outputPath != null) {
			for (ClassInterface ci : si.classes) {
				File f = new File(outputPath + File.separator + ci.name + ".java");
				String classContent = ci.toString();
				BufferedWriter bw = new BufferedWriter(new FileWriter(f));
				bw.write(classContent);
				bw.close();
			}
		}
		return out.toString();
	}

	private void addExtendedFields(ClassInterface ci) {
		if (ci.extendList.isEmpty()) return; // nothing to do
		
		for (String sCi : ci.extendList) {
			addExtendedFields(classMap.get(sCi));
		}
		for (String sCi : ci.extendList) {
			ClassInterface cci = classMap.get(sCi);
			for (Field fcci : cci.fields) {
				boolean contains = false;
				for (Field fci : ci.fields) {
					// If field overrides another one, copy it only once
					contains = contains || fci.name.equals(fcci.name);
				}
				if (!contains) ci.fields.add(fcci);
			}
		}
	}
}