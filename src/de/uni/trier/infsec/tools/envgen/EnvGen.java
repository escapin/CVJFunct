package de.uni.trier.infsec.tools.envgen;

import japa.parser.JavaParser;
import japa.parser.ast.CompilationUnit;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileFilter;
import java.io.FileReader;
import java.io.FileWriter;

import de.uni.trier.infsec.tools.envgen.InterfaceGenerator.InterfaceGenerationVisitor;

public class EnvGen {

	private final FileFilter fileFilter = new FileFilter() {
		@Override
		public boolean accept(File pathname) {
			return pathname.isDirectory() || pathname.getName().endsWith(".java");
		}
	};

	/*
	 * This class accepts path to a java file or folder and will do following steps: 1. It will generate interface IE (using class InterfaceGenerator) 2. It will validate the generated interface to
	 * comply with the conditions from Appendix D.A (and abort in case of violation) 3. It will generate the System E to the output file
	 * 
	 * Usage: Parameter 1 = Path to source file or Folder, all .java files will be accepted Parameter 2 = Path to output folder - Source code of System E will be stored here Parameter 3 = Validation
	 * rules allow to specify "accepted classes". Optionally a file containing a comma separated list of classes goes here. (fully specified class names like 'java.util.HashMap' except 'java.lang'
	 * package, here only use classname like 'String') Parameter 4 = Package of generated Environment.java - by default package is "environment"
	 * 
	 * Notes: - For optimal class recognition do not use wildcard-imports (java.util.*) but fully qualified imports (java.util.HashMap) - Classes must not extend imported classes but only ones from IE
	 *        - If code contains constructor, just leave it out from IE or generate IE and fail on verification? 
	 *        - Accept all primitive types (float, long,...) or only byte, byte[], void and int?
	 */
	public static void main(String[] args) throws Exception {
		if (args.length < 2) {
			System.out.println("Missing parameter\nUsage: <path-to-file/folder IN> <path-to-output-file> [<path-to-accepted-types-list>] [name of environment package]");
			return;
		}
		String types = args.length > 2 ? args[2] : null;
		String packagename = args.length > 3 ? args[3] : null;
		new EnvGen().doWork(args[0], args[1], types, packagename);
	}

	public void doWork(String pathIn, String fileOut, String acceptedTypes, String packageName) throws Exception {
		File f = new File(pathIn);
		if (!f.exists()) {
			System.out.println(String.format("File %s does not exist", f.getAbsolutePath()));
			return;
		}

		SystemInterface sInterface = new SystemInterface();
		sInterface.mainPackage = packageName != null ? packageName : "environment";
		sInterface = read(pathIn, sInterface);

		System.out.println("################## BEGIN: Generated Interface for Java code #####################\n");
		System.out.println(sInterface.toString());
		System.out.println("################## END: Generated Interface for Java code #####################\n");

		ConditionVerifier cv = new ConditionVerifier(sInterface, acceptedTypes);
		if (!cv.verifyConditions(sInterface)) {
			System.out.println("\n################## Generated Interface could not be verified ##################\n\n");
			return;
		}
		System.out.println("\n################## Generated Interface successfully verified ##################\n\n");

		SystemGenerator sg = new SystemGenerator();
		System.out.println("################## BEGIN: Generated System for Interface ######################\n");
		String system = sg.generate(sInterface, fileOut);
		System.out.println(system);
		System.out.println("################## END: Generated System for Interface ######################\n");

		String packageDir = "environment";
		if (packageName != null && !packageName.equals("")) {
			packageDir = packageName.replaceAll("\\.", "/");
		}
		File foutDir = new File(fileOut + File.separator + packageDir + File.separator);
		foutDir.mkdirs();

		File fout = new File(foutDir.getAbsolutePath() + File.separator + "Env.java");
		BufferedWriter bw = new BufferedWriter(new FileWriter(fout));
		bw.write(system);
		bw.close();
	}

	public SystemInterface read(String path, SystemInterface sInterface) throws Exception {
		File f = new File(path);
		if (f.isDirectory()) {
			for (File ff : f.listFiles(fileFilter)) {
				if (ff.isDirectory()) {
					sInterface = read(ff.getAbsolutePath(), sInterface);
				} else {
					sInterface = readFile(ff, sInterface);
				}
			}
		} else {
			sInterface = readFile(f, sInterface);
		}
		return sInterface;
	}

	private SystemInterface readFile(File ff, SystemInterface sInterface) throws Exception {
		BufferedReader read = new BufferedReader(new FileReader(ff));
		StringBuffer sb = new StringBuffer();
		while (read.ready())
			sb.append(read.readLine().replaceAll("<(.*?)>", "") + "\n");
		// Needed to remove java 7 specific generics, like Hashmap<String, String> ... new Hashmap<>()
		read.close();

		CompilationUnit compilation = JavaParser.parse(new ByteArrayInputStream(sb.toString().getBytes("UTF-8")));
		sInterface = (SystemInterface) (new InterfaceGenerationVisitor()).visit(compilation, sInterface);
		return sInterface;
	}

}
