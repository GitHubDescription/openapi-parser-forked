/*
#    Copyright (C) 2016 Alexandre Teyar

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#    limitations under the License. 
*/

package swurg.process;

import com.google.common.base.Strings;
import io.swagger.models.Swagger;
import io.swagger.parser.SwaggerParser;
import java.io.File;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.collections4.MapUtils;
import burp.BurpExtender;
import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;

public class Loader {
  public static BurpExtender burp = BurpExtender.getInstance();
  private IBurpExtenderCallbacks callbacks = burp.getCallbacks();
  PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
  PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
  public Swagger process(String resource) {

    if (Strings.isNullOrEmpty(resource)) {
      throw new IllegalArgumentException("No file or URL specified");
    }

    if (new File(resource).exists()) {
      assert true;
    } else {
      try {
        new URL(resource).toURI();
      } catch (MalformedURLException | URISyntaxException e) {
        throw new IllegalArgumentException(String.format("%s does not exist or is an invalid URL", resource));
      }
    }

    Swagger swagger = new SwaggerParser().read(resource);

    if (swagger == null) {
      throw new NullPointerException(
          String.format("The OpenAPI specification contained in %s is ill formed and cannot be parsed", resource));
    } else {
      validateSpecification(swagger, resource);
      return swagger;
    }
  }

  private void validateSpecification(Swagger swagger, String resource) {
    // As discussed in https://github.com/AresS31/swurg/issues/56, the host and schemes are not even supported in 3.0.2 OpenAPI definitions
    // Therefore, the code here is commented out, left for tracability
    if (Strings.isNullOrEmpty(swagger.getHost())) {
    //   throw new IllegalArgumentException(
    //       String.format(
    //           "The OpenAPI specification contained in %s is missing the mandatory field: 'host'",
    //           resource));
      stdout.println(String.format("The OpenAPI specification contained in %s is missing the field: 'host'", resource));
    }

    if (CollectionUtils.isEmpty(swagger.getSchemes())) {
    //   throw new IllegalArgumentException(
    //       String.format(
    //           "The OpenAPI specification contained in %s is missing the mandatory field: 'schemes'",
    //           resource));
      stdout.println(String.format("The OpenAPI specification contained in %s is missing the field: 'schemes'", resource));
    }

    if (MapUtils.isEmpty(swagger.getPaths())) {
      throw new IllegalArgumentException(
          String.format(
              "The OpenAPI specification contained in %s is missing the mandatory field: 'paths'",
              resource));
    }
  }

}
