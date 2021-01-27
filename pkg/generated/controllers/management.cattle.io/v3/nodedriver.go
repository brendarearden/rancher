/*
Copyright 2021 Rancher Labs, Inc.

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

// Code generated by main. DO NOT EDIT.

package v3

import (
	"context"
	"time"

	"github.com/rancher/lasso/pkg/client"
	"github.com/rancher/lasso/pkg/controller"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/apply"
	"github.com/rancher/wrangler/pkg/condition"
	"github.com/rancher/wrangler/pkg/generic"
	"github.com/rancher/wrangler/pkg/kv"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
)

type NodeDriverHandler func(string, *v3.NodeDriver) (*v3.NodeDriver, error)

type NodeDriverController interface {
	generic.ControllerMeta
	NodeDriverClient

	OnChange(ctx context.Context, name string, sync NodeDriverHandler)
	OnRemove(ctx context.Context, name string, sync NodeDriverHandler)
	Enqueue(name string)
	EnqueueAfter(name string, duration time.Duration)

	Cache() NodeDriverCache
}

type NodeDriverClient interface {
	Create(*v3.NodeDriver) (*v3.NodeDriver, error)
	Update(*v3.NodeDriver) (*v3.NodeDriver, error)
	UpdateStatus(*v3.NodeDriver) (*v3.NodeDriver, error)
	Delete(name string, options *metav1.DeleteOptions) error
	Get(name string, options metav1.GetOptions) (*v3.NodeDriver, error)
	List(opts metav1.ListOptions) (*v3.NodeDriverList, error)
	Watch(opts metav1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v3.NodeDriver, err error)
}

type NodeDriverCache interface {
	Get(name string) (*v3.NodeDriver, error)
	List(selector labels.Selector) ([]*v3.NodeDriver, error)

	AddIndexer(indexName string, indexer NodeDriverIndexer)
	GetByIndex(indexName, key string) ([]*v3.NodeDriver, error)
}

type NodeDriverIndexer func(obj *v3.NodeDriver) ([]string, error)

type nodeDriverController struct {
	controller    controller.SharedController
	client        *client.Client
	gvk           schema.GroupVersionKind
	groupResource schema.GroupResource
}

func NewNodeDriverController(gvk schema.GroupVersionKind, resource string, namespaced bool, controller controller.SharedControllerFactory) NodeDriverController {
	c := controller.ForResourceKind(gvk.GroupVersion().WithResource(resource), gvk.Kind, namespaced)
	return &nodeDriverController{
		controller: c,
		client:     c.Client(),
		gvk:        gvk,
		groupResource: schema.GroupResource{
			Group:    gvk.Group,
			Resource: resource,
		},
	}
}

func FromNodeDriverHandlerToHandler(sync NodeDriverHandler) generic.Handler {
	return func(key string, obj runtime.Object) (ret runtime.Object, err error) {
		var v *v3.NodeDriver
		if obj == nil {
			v, err = sync(key, nil)
		} else {
			v, err = sync(key, obj.(*v3.NodeDriver))
		}
		if v == nil {
			return nil, err
		}
		return v, err
	}
}

func (c *nodeDriverController) Updater() generic.Updater {
	return func(obj runtime.Object) (runtime.Object, error) {
		newObj, err := c.Update(obj.(*v3.NodeDriver))
		if newObj == nil {
			return nil, err
		}
		return newObj, err
	}
}

func UpdateNodeDriverDeepCopyOnChange(client NodeDriverClient, obj *v3.NodeDriver, handler func(obj *v3.NodeDriver) (*v3.NodeDriver, error)) (*v3.NodeDriver, error) {
	if obj == nil {
		return obj, nil
	}

	copyObj := obj.DeepCopy()
	newObj, err := handler(copyObj)
	if newObj != nil {
		copyObj = newObj
	}
	if obj.ResourceVersion == copyObj.ResourceVersion && !equality.Semantic.DeepEqual(obj, copyObj) {
		return client.Update(copyObj)
	}

	return copyObj, err
}

func (c *nodeDriverController) AddGenericHandler(ctx context.Context, name string, handler generic.Handler) {
	c.controller.RegisterHandler(ctx, name, controller.SharedControllerHandlerFunc(handler))
}

func (c *nodeDriverController) AddGenericRemoveHandler(ctx context.Context, name string, handler generic.Handler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), handler))
}

func (c *nodeDriverController) OnChange(ctx context.Context, name string, sync NodeDriverHandler) {
	c.AddGenericHandler(ctx, name, FromNodeDriverHandlerToHandler(sync))
}

func (c *nodeDriverController) OnRemove(ctx context.Context, name string, sync NodeDriverHandler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), FromNodeDriverHandlerToHandler(sync)))
}

func (c *nodeDriverController) Enqueue(name string) {
	c.controller.Enqueue("", name)
}

func (c *nodeDriverController) EnqueueAfter(name string, duration time.Duration) {
	c.controller.EnqueueAfter("", name, duration)
}

func (c *nodeDriverController) Informer() cache.SharedIndexInformer {
	return c.controller.Informer()
}

func (c *nodeDriverController) GroupVersionKind() schema.GroupVersionKind {
	return c.gvk
}

func (c *nodeDriverController) Cache() NodeDriverCache {
	return &nodeDriverCache{
		indexer:  c.Informer().GetIndexer(),
		resource: c.groupResource,
	}
}

func (c *nodeDriverController) Create(obj *v3.NodeDriver) (*v3.NodeDriver, error) {
	result := &v3.NodeDriver{}
	return result, c.client.Create(context.TODO(), "", obj, result, metav1.CreateOptions{})
}

func (c *nodeDriverController) Update(obj *v3.NodeDriver) (*v3.NodeDriver, error) {
	result := &v3.NodeDriver{}
	return result, c.client.Update(context.TODO(), "", obj, result, metav1.UpdateOptions{})
}

func (c *nodeDriverController) UpdateStatus(obj *v3.NodeDriver) (*v3.NodeDriver, error) {
	result := &v3.NodeDriver{}
	return result, c.client.UpdateStatus(context.TODO(), "", obj, result, metav1.UpdateOptions{})
}

func (c *nodeDriverController) Delete(name string, options *metav1.DeleteOptions) error {
	if options == nil {
		options = &metav1.DeleteOptions{}
	}
	return c.client.Delete(context.TODO(), "", name, *options)
}

func (c *nodeDriverController) Get(name string, options metav1.GetOptions) (*v3.NodeDriver, error) {
	result := &v3.NodeDriver{}
	return result, c.client.Get(context.TODO(), "", name, result, options)
}

func (c *nodeDriverController) List(opts metav1.ListOptions) (*v3.NodeDriverList, error) {
	result := &v3.NodeDriverList{}
	return result, c.client.List(context.TODO(), "", result, opts)
}

func (c *nodeDriverController) Watch(opts metav1.ListOptions) (watch.Interface, error) {
	return c.client.Watch(context.TODO(), "", opts)
}

func (c *nodeDriverController) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (*v3.NodeDriver, error) {
	result := &v3.NodeDriver{}
	return result, c.client.Patch(context.TODO(), "", name, pt, data, result, metav1.PatchOptions{}, subresources...)
}

type nodeDriverCache struct {
	indexer  cache.Indexer
	resource schema.GroupResource
}

func (c *nodeDriverCache) Get(name string) (*v3.NodeDriver, error) {
	obj, exists, err := c.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(c.resource, name)
	}
	return obj.(*v3.NodeDriver), nil
}

func (c *nodeDriverCache) List(selector labels.Selector) (ret []*v3.NodeDriver, err error) {

	err = cache.ListAll(c.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v3.NodeDriver))
	})

	return ret, err
}

func (c *nodeDriverCache) AddIndexer(indexName string, indexer NodeDriverIndexer) {
	utilruntime.Must(c.indexer.AddIndexers(map[string]cache.IndexFunc{
		indexName: func(obj interface{}) (strings []string, e error) {
			return indexer(obj.(*v3.NodeDriver))
		},
	}))
}

func (c *nodeDriverCache) GetByIndex(indexName, key string) (result []*v3.NodeDriver, err error) {
	objs, err := c.indexer.ByIndex(indexName, key)
	if err != nil {
		return nil, err
	}
	result = make([]*v3.NodeDriver, 0, len(objs))
	for _, obj := range objs {
		result = append(result, obj.(*v3.NodeDriver))
	}
	return result, nil
}

type NodeDriverStatusHandler func(obj *v3.NodeDriver, status v3.NodeDriverStatus) (v3.NodeDriverStatus, error)

type NodeDriverGeneratingHandler func(obj *v3.NodeDriver, status v3.NodeDriverStatus) ([]runtime.Object, v3.NodeDriverStatus, error)

func RegisterNodeDriverStatusHandler(ctx context.Context, controller NodeDriverController, condition condition.Cond, name string, handler NodeDriverStatusHandler) {
	statusHandler := &nodeDriverStatusHandler{
		client:    controller,
		condition: condition,
		handler:   handler,
	}
	controller.AddGenericHandler(ctx, name, FromNodeDriverHandlerToHandler(statusHandler.sync))
}

func RegisterNodeDriverGeneratingHandler(ctx context.Context, controller NodeDriverController, apply apply.Apply,
	condition condition.Cond, name string, handler NodeDriverGeneratingHandler, opts *generic.GeneratingHandlerOptions) {
	statusHandler := &nodeDriverGeneratingHandler{
		NodeDriverGeneratingHandler: handler,
		apply:                       apply,
		name:                        name,
		gvk:                         controller.GroupVersionKind(),
	}
	if opts != nil {
		statusHandler.opts = *opts
	}
	controller.OnChange(ctx, name, statusHandler.Remove)
	RegisterNodeDriverStatusHandler(ctx, controller, condition, name, statusHandler.Handle)
}

type nodeDriverStatusHandler struct {
	client    NodeDriverClient
	condition condition.Cond
	handler   NodeDriverStatusHandler
}

func (a *nodeDriverStatusHandler) sync(key string, obj *v3.NodeDriver) (*v3.NodeDriver, error) {
	if obj == nil {
		return obj, nil
	}

	origStatus := obj.Status.DeepCopy()
	obj = obj.DeepCopy()
	newStatus, err := a.handler(obj, obj.Status)
	if err != nil {
		// Revert to old status on error
		newStatus = *origStatus.DeepCopy()
	}

	if a.condition != "" {
		if errors.IsConflict(err) {
			a.condition.SetError(&newStatus, "", nil)
		} else {
			a.condition.SetError(&newStatus, "", err)
		}
	}
	if !equality.Semantic.DeepEqual(origStatus, &newStatus) {
		if a.condition != "" {
			// Since status has changed, update the lastUpdatedTime
			a.condition.LastUpdated(&newStatus, time.Now().UTC().Format(time.RFC3339))
		}

		var newErr error
		obj.Status = newStatus
		newObj, newErr := a.client.UpdateStatus(obj)
		if err == nil {
			err = newErr
		}
		if newErr == nil {
			obj = newObj
		}
	}
	return obj, err
}

type nodeDriverGeneratingHandler struct {
	NodeDriverGeneratingHandler
	apply apply.Apply
	opts  generic.GeneratingHandlerOptions
	gvk   schema.GroupVersionKind
	name  string
}

func (a *nodeDriverGeneratingHandler) Remove(key string, obj *v3.NodeDriver) (*v3.NodeDriver, error) {
	if obj != nil {
		return obj, nil
	}

	obj = &v3.NodeDriver{}
	obj.Namespace, obj.Name = kv.RSplit(key, "/")
	obj.SetGroupVersionKind(a.gvk)

	return nil, generic.ConfigureApplyForObject(a.apply, obj, &a.opts).
		WithOwner(obj).
		WithSetID(a.name).
		ApplyObjects()
}

func (a *nodeDriverGeneratingHandler) Handle(obj *v3.NodeDriver, status v3.NodeDriverStatus) (v3.NodeDriverStatus, error) {
	objs, newStatus, err := a.NodeDriverGeneratingHandler(obj, status)
	if err != nil {
		return newStatus, err
	}

	return newStatus, generic.ConfigureApplyForObject(a.apply, obj, &a.opts).
		WithOwner(obj).
		WithSetID(a.name).
		ApplyObjects(objs...)
}
