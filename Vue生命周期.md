# Vue生命周期

`Vue`实例创建的过程中，需要经历一系列初始化过程，包括数据监听、模板编译、`DOM`挂载等，在这个过程中会调用一些`生命周期钩子函数`，这样就可以在`Vue`实例创建的不同阶段做一些事

* beforeCreate

  在实例初始化之后，数据观测和`event/watcher`事件配置之前调用

* created

  实例创建完成后立即调用。数据观测、属性和方法的运算、`watch/event`事件回调已经完成，但是`$el`属性还不可以。在这里可以进行大多数操作，除了`DOM`相关，`DOM`操作可以使用`nextTick`

* beforeMount

  挂载开始之前被调用，相关的`render`首次被调用

* mounted

  实例挂载完成后调用，在这里可以进行`DOM`操作

* beforeUpdate

  数据更新时，`VNode`打补丁之前。在这里可以访问现有的`DOM`

* updated

  `VNode`重新渲染和打补丁之后调用。在这里可以进行一些`DOM`操作

* activated

  被`keep-alive`缓存的组件激活时调用

* deactivated

  被`keep-alive`缓存的组件停用时调用

* beforeDestroy

  实例销毁之前调用，在这里实例完全可用

* destroyed

  实例销毁之后调用，`Vue`实例所有指令解绑，所有事件监听器被移除，所有子组件也都被销毁

* errorCaptured

  当捕获一个来自子孙组件的错误时调用