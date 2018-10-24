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
package org.apache.xml.security.transforms.implementations;

import java.io.OutputStream;

import javax.xml.transform.TransformerException;

import org.apache.xml.security.exceptions.XMLSecurityRuntimeException;
import org.apache.xml.security.signature.NodeFilter;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.transforms.TransformSpi;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.utils.XPathAPI;
import org.apache.xml.security.utils.XPathFactory;
import org.w3c.dom.DOMException;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Class TransformXPath
 *
 * Implements the <CODE>http://www.w3.org/TR/1999/REC-xpath-19991116</CODE>
 * transform.
 *
 * @see <a href="http://www.w3.org/TR/1999/REC-xpath-19991116">XPath</a>
 *
 */
public class TransformXPath extends TransformSpi {

    /** Field implementedTransformURI */
    public static final String implementedTransformURI = Transforms.TRANSFORM_XPATH;

    /**
     * Method engineGetURI
     *
     * {@inheritDoc}
     */
    protected String engineGetURI() {
        return implementedTransformURI;
    }

    /**
     * Method enginePerformTransform
     * {@inheritDoc}
     * @param input
     *
     * @throws TransformationException
     */
    protected XMLSignatureInput enginePerformTransform(
        XMLSignatureInput input, OutputStream os, Transform transformObject
    ) throws TransformationException {
        try {
            /**
             * If the actual input is an octet stream, then the application MUST
             * convert the octet stream to an XPath node-set suitable for use by
             * Canonical XML with Comments. (A subsequent application of the
             * REQUIRED Canonical XML algorithm would strip away these comments.)
             *
             * ...
             *
             * The evaluation of this expression includes all of the document's nodes
             * (including comments) in the node-set representing the octet stream.
             */
            Element xpathElement =
                XMLUtils.selectDsNode(
                    transformObject.getElement().getFirstChild(), Constants._TAG_XPATH, 0);

            if (xpathElement == null) {
                Object[] exArgs = { "ds:XPath", "Transform" };

                throw new TransformationException("xml.WrongContent", exArgs);
            }
            Node xpathnode = xpathElement.getFirstChild();
            if (xpathnode == null) {
                throw new DOMException(
                    DOMException.HIERARCHY_REQUEST_ERR, "Text must be in ds:Xpath"
                );
            }
            String str = XMLUtils.getStrFromNode(xpathnode);
            input.setNeedsToBeExpanded(needsCircumvent(str));

            XPathFactory xpathFactory = XPathFactory.newInstance();
            XPathAPI xpathAPIInstance = xpathFactory.newXPathAPI();
            input.addNodeFilter(new XPathNodeFilter(xpathElement, xpathnode, str, xpathAPIInstance));
            input.setNodeSet(true);
            return input;
        } catch (DOMException ex) {
            throw new TransformationException(ex);
        }
    }

    /**
     * @param str
     * @return true if needs to be circumvent for bug.
     */
    private boolean needsCircumvent(String str) {
        return str.indexOf("namespace") != -1 || str.indexOf("name()") != -1;
    }

    static class XPathNodeFilter implements NodeFilter {

        XPathAPI xPathAPI;
        Node xpathnode;
        Element xpathElement;
        String str;

        XPathNodeFilter(Element xpathElement, Node xpathnode, String str, XPathAPI xPathAPI) {
            this.xpathnode = xpathnode;
            this.str = str;
            this.xpathElement = xpathElement;
            this.xPathAPI = xPathAPI;
        }

        /**
         * @see org.apache.xml.security.signature.NodeFilter#isNodeInclude(org.w3c.dom.Node)
         */
        public int isNodeInclude(Node currentNode) {
            try {
                boolean include = xPathAPI.evaluate(currentNode, xpathnode, str, xpathElement);
                if (include) {
                    return 1;
                }
                return 0;
            } catch (TransformerException e) {
                Object[] eArgs = {currentNode};
                throw new XMLSecurityRuntimeException("signature.Transform.node", eArgs, e);
            } catch (Exception e) {
                Object[] eArgs = {currentNode, currentNode.getNodeType()};
                throw new XMLSecurityRuntimeException("signature.Transform.nodeAndType",eArgs, e);
            }
        }

        public int isNodeIncludeDO(Node n, int level) {
            return isNodeInclude(n);
        }

    }
}
