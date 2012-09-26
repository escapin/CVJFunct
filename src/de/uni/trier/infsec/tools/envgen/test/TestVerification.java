package de.uni.trier.infsec.tools.envgen.test;

import japa.parser.JavaParser;
import japa.parser.ast.CompilationUnit;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;

import junit.framework.TestCase;

import org.junit.Test;

import de.uni.trier.infsec.tools.envgen.ConditionVerifier;
import de.uni.trier.infsec.tools.envgen.SystemGenerator;
import de.uni.trier.infsec.tools.envgen.SystemInterface;
import de.uni.trier.infsec.tools.envgen.InterfaceGenerator.InterfaceGenerationVisitor;

public class TestVerification extends TestCase {

	@Test
	public void testVerification01() throws Exception {
		File f = new File(this.getClass().getResource("TestClassCondition01.avaj").toURI());
		
		if (!f.exists()) {
			System.out.println(String.format("File %s does not exist", f.getAbsolutePath()));
			return;
		}

		SystemInterface sInterface = new SystemInterface();
		sInterface = readFile(f, sInterface);

		System.out.println("################## BEGIN: Generated Interface for Java code #####################\n");
		System.out.println(sInterface.toString());
		System.out.println("################## END: Generated Interface for Java code #####################\n");

		ConditionVerifier cv = new ConditionVerifier(sInterface, null);
		assertFalse(cv.verifyConditions(sInterface));
	}
	
	@Test
	public void testVerification02() throws Exception {
		File f = new File(this.getClass().getResource("TestClassCondition02.avaj").toURI());
		
		if (!f.exists()) {
			System.out.println(String.format("File %s does not exist", f.getAbsolutePath()));
			return;
		}
		
		SystemInterface sInterface = new SystemInterface();
		sInterface = readFile(f, sInterface);
		
		System.out.println("################## BEGIN: Generated Interface for Java code #####################\n");
		System.out.println(sInterface.toString());
		System.out.println("################## END: Generated Interface for Java code #####################\n");
		
		ConditionVerifier cv = new ConditionVerifier(sInterface, null);
		assertFalse(cv.verifyConditions(sInterface));
	}
	
	@Test
	public void testVerification03() throws Exception {
		File f = new File(this.getClass().getResource("TestClassCondition03.avaj").toURI());
		
		if (!f.exists()) {
			System.out.println(String.format("File %s does not exist", f.getAbsolutePath()));
			return;
		}
		
		SystemInterface sInterface = new SystemInterface();
		sInterface = readFile(f, sInterface);
		
		System.out.println("################## BEGIN: Generated Interface for Java code #####################\n");
		System.out.println(sInterface.toString());
		System.out.println("################## END: Generated Interface for Java code #####################\n");
		
		ConditionVerifier cv = new ConditionVerifier(sInterface, null);
		assertFalse(cv.verifyConditions(sInterface));
	}
	
	@Test
	public void testVerification04() throws Exception {
		File f = new File(this.getClass().getResource("TestClassCondition04.avaj").toURI());
		
		if (!f.exists()) {
			System.out.println(String.format("File %s does not exist", f.getAbsolutePath()));
			return;
		}
		
		SystemInterface sInterface = new SystemInterface();
		sInterface = readFile(f, sInterface);
		
		System.out.println("################## BEGIN: Generated Interface for Java code #####################\n");
		System.out.println(sInterface.toString());
		System.out.println("################## END: Generated Interface for Java code #####################\n");
		
		ConditionVerifier cv = new ConditionVerifier(sInterface, null);
		assertFalse(cv.verifyConditions(sInterface));
	}
	
	@Test
	public void testVerification05() throws Exception {
		File f = new File(this.getClass().getResource("TestClassSystemGeneration.avaj").toURI());
		
		if (!f.exists()) {
			System.out.println(String.format("File %s does not exist", f.getAbsolutePath()));
			return;
		}
		
		SystemInterface sInterface = new SystemInterface();
		sInterface = readFile(f, sInterface);
		
		System.out.println("################## BEGIN: Generated Interface for Java code #####################\n");
		System.out.println(sInterface.toString());
		System.out.println("################## END: Generated Interface for Java code #####################\n");
		
		ConditionVerifier cv = new ConditionVerifier(sInterface, null);
		assertTrue(cv.verifyConditions(sInterface));
		System.out.println("\n################## Generated Interface successfully verified ##################\n\n");

		SystemGenerator sg = new SystemGenerator();		
		System.out.println("################## BEGIN: Generated System for Interface ######################\n");
		String system = sg.generate(sInterface, null);
		System.out.println(system);
		System.out.println("################## END: Generated System for Interface ######################\n");
	}
	
		
	private SystemInterface readFile(File ff, SystemInterface sInterface) throws Exception {
		BufferedReader read = new BufferedReader(new FileReader(ff));
		StringBuffer sb = new StringBuffer();
		while (read.ready()) sb.append(read.readLine().replaceAll("<(.*?)>", "") + "\n");
		// Needed to remove java 7 specific generics, like Hashmap<String, String> ... new Hashmap<>()
		read.close();
		
		CompilationUnit compilation = JavaParser.parse(new ByteArrayInputStream(sb.toString().getBytes("UTF-8")));
		sInterface = (SystemInterface) (new InterfaceGenerationVisitor()).visit(compilation, sInterface);
		return sInterface;
	}
	
}
