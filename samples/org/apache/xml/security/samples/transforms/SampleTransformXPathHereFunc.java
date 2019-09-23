/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.xml.security.samples.transforms;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.samples.DSNamespaceContext;
import org.apache.xml.security.samples.SampleUtils;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * This class demonstrates the use of a Transform for XSLT. The
 * <CODE>xsl:stylesheet</CODE> is directly embedded in the <CODE>ds:Transform</CODE>,
 * so the {@link Transform} object is created by using the Element.
 *
 * @author Christian Geuer-Pollmann
 * @version %I%, %G%
 */
public class SampleTransformXPathHereFunc {

    /**
     * Method main
     *
     * @param args
     * @throws Exception
     */
    public static void main(String args[]) throws Exception {
        String inputStr =
            "<?xml version=\"1.0\"?>" + "\n"
            + "<Document>" + "\n"
            + "   <Data attr='attrValue'>text in Data</Data>" + "\n"
            + "<Signature xmlns='http://www.w3.org/2000/09/xmldsig#'>" + "\n"
            + "     <SignedInfo>" + "\n"
            + "       <Reference>" + "\n"
            + "         <Transforms>" + "\n"
            + "           <Transform xmlns:ds='http://www.w3.org/2000/09/xmldsig#' Algorithm='http://www.w3.org/TR/1999/REC-xpath-19991116'>" + "\n"
            + "             <XPath>count(ancestor-or-self::ds:Signature | here()/ancestor::ds:Signature[1]) &gt; count(ancestor-or-self::ds:Signature)</XPath>" + "\n"
            + "           </Transform>" + "\n"
            + "           <Transform Algorithm='http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments' />" + "\n"
            + "           <Transform Algorithm='http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments' />" + "\n"
            + "           <Transform Algorithm='http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments' />" + "\n"
            + "           <Transform Algorithm='http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments' />" + "\n"
            + "           <Transform Algorithm='http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments' />" + "\n"
            + "         </Transforms>" + "\n"
            + "       </Reference>" + "\n"
            + "     </SignedInfo>" + "\n"
            + "   </Signature>"
            + "</Document>"
            ;
        
        org.apache.xml.security.Init.init();
        javax.xml.parsers.DocumentBuilderFactory dbf =
            javax.xml.parsers.DocumentBuilderFactory.newInstance();

        dbf.setNamespaceAware(true);

        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        org.w3c.dom.Document doc =
            db.parse(new java.io.ByteArrayInputStream(inputStr.getBytes()));
        
        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());

        String expression = "/Document/ds:Signature[1]/ds:SignedInfo/ds:Reference[1]/ds:Transforms";
        Element transformsElem = 
            (Element) xpath.evaluate(expression, doc, XPathConstants.NODE);
        
        Transforms transforms = new Transforms(transformsElem, "memory://");
        XMLSignatureInput input = new XMLSignatureInput((Node) doc);

        // input.setCanonicalizerURI(Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS);

        XMLSignatureInput result = transforms.performTransforms(input);

        System.out.println(new String(result.getBytes()));
    }
    
}
