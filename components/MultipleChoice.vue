<template>
	<b-form @submit.prevent="handleSubmit">
		<b-form-group label="Valitse hedelmät">
			<b-form-checkbox-group
				v-model="fruitCollection"
				:options="items"
				stacked
			/>
		</b-form-group>
		<b-button type="submit" class="btn-primary">Lähetä</b-button>
	</b-form>
</template>

<script>
export default {
	name: 'MultipleChoice',
	data() {
		return {
			items: [
				{ text: 'Apple', value: 'apple' },
				{ text: 'Orange', value: 'orange' },
				{ text: 'Mango', value: 'mango' },
				{ text: 'Cherry', value: 'cherry' }
			],
			fruitCollection: []
		}
	},
	methods: {
		handleSubmit() {
			alert(JSON.stringify(this.fruitCollection))
		}
	}
}
</script>
