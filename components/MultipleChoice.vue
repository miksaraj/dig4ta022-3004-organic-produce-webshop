<template>
	<form @submit.prevent="handleSubmit">
		<div
			class="form-group form-check"
			v-for="item in Items"
			v-bind:key="item.id"
		>
			<label class="form-check-label" :for="item.id">{{
				item.name
			}}</label>
			<input
				type="checkbox"
				v-model="user.fruitCollection"
				:id="item.name"
				:value="item.name"
			/>
		</div>

		<div class="form-group">
			{{ user.fruitCollection }}
		</div>

		<div class="form-group">
			<button class="btn btn-primary">Submit</button>
		</div>
	</form>
</template>

<script>
export default {
	name: 'multipleChoice',
	data() {
		return {
			Items: [
				{
					name: 'Apple'
				},
				{
					name: 'Orange'
				},
				{
					name: 'Mengo'
				},
				{
					name: 'Cherry'
				}
			],
			user: {
				fruitCollection: []
			}
		}
	},
	methods: {
		handleSubmit() {
			alert(JSON.stringify(this.user))
		}
	}
}
</script>
