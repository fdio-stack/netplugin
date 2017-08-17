/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package fake

import (
	v1alpha1 "github.com/contiv/client-go/kubernetes/typed/rbac/v1alpha1"
	rest "github.com/contiv/client-go/rest"
	testing "github.com/contiv/client-go/testing"
)

type FakeRbacV1alpha1 struct {
	*testing.Fake
}

func (c *FakeRbacV1alpha1) ClusterRoles() v1alpha1.ClusterRoleInterface {
	return &FakeClusterRoles{c}
}

func (c *FakeRbacV1alpha1) ClusterRoleBindings() v1alpha1.ClusterRoleBindingInterface {
	return &FakeClusterRoleBindings{c}
}

func (c *FakeRbacV1alpha1) Roles(namespace string) v1alpha1.RoleInterface {
	return &FakeRoles{c, namespace}
}

func (c *FakeRbacV1alpha1) RoleBindings(namespace string) v1alpha1.RoleBindingInterface {
	return &FakeRoleBindings{c, namespace}
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *FakeRbacV1alpha1) RESTClient() rest.Interface {
	var ret *rest.RESTClient
	return ret
}